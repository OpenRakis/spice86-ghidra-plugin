package spice86.importer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import spice86.tools.Context;
import spice86.tools.LabelManager;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;
import spice86.tools.config.ByteModificationRecord;
import spice86.tools.config.ExecutionFlow;
import spice86.tools.config.PluginConfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class RuntimeEvidenceImporter extends ObjectWithContextAndLog {
  private static final String BOOKMARK_TYPE = "Spice86";
  private static final int EXECUTED_BLOCK_MAX_GAP = 0x0F;

  private final Program program;
  private final Listing listing;
  private final Memory memory;
  private final BookmarkManager bookmarkManager;
  private final ReferenceManager referenceManager;
  private final LabelManager labelManager;
  private final FunctionCreator functionCreator;
  private long addressDelta;

  RuntimeEvidenceImporter(Context context) {
    super(context);
    this.program = context.getProgram();
    this.listing = program.getListing();
    this.memory = program.getMemory();
    this.bookmarkManager = program.getBookmarkManager();
    this.referenceManager = program.getReferenceManager();
    this.labelManager = new LabelManager(context);
    this.functionCreator = new FunctionCreator(context, labelManager);
  }

  ImportSummary importEvidence(PluginConfiguration pluginConfiguration) throws Exception {
    ExecutionFlow executionFlow = pluginConfiguration.getExecutionFlow();
    verifyAddressSpaceCompatibility(pluginConfiguration, executionFlow);

    ImportSummary summary = new ImportSummary();
    summary.recordedFunctions = importRecordedFunctions(pluginConfiguration.getRecordedFunctions());
    summary.callReferences =
        importFlowReferences(executionFlow.getCallsFromTo(), RefType.COMPUTED_CALL, "Dynamic Call Target", "call");
    summary.jumpReferences =
        importFlowReferences(executionFlow.getJumpsFromTo(), RefType.COMPUTED_JUMP, "Dynamic Jump Target", "jump");
    summary.returnTargets = importReturnTargets(executionFlow.getRetsFromTo());
    summary.executedBlocks = importExecutedBlocks(executionFlow.getExecutedInstructions());
    summary.modifiedExecutableBytes = importExecutableByteWrites(executionFlow.getExecutableAddressWrittenBy());
    return summary;
  }

  private void verifyAddressSpaceCompatibility(
      PluginConfiguration pluginConfiguration,
      ExecutionFlow executionFlow
  ) {
    SegmentedAddress sample = findSampleAddress(pluginConfiguration, executionFlow);
    if (sample == null) {
      return;
    }
    addressDelta = inferAddressDelta(pluginConfiguration, executionFlow);
    Address address = toProgramAddress(sample);
    if (memory.contains(address)) {
      log.info("Using Spice86 -> Ghidra address delta " + Utils.toHexWith0X(addressDelta));
      return;
    }
    throw new IllegalStateException(
        "Current program does not contain Spice86 address "
            + Utils.toHexWith0X(sample.toPhysical())
            + " translated to "
            + Utils.toHexWith0X(sample.toPhysical() + addressDelta)
            + ". Import a program whose address space matches spice86dumpGhidraSymbols.txt / physical dump addresses."
    );
  }

  private SegmentedAddress findSampleAddress(PluginConfiguration pluginConfiguration, ExecutionFlow executionFlow) {
    if (!pluginConfiguration.getRecordedFunctions().isEmpty()) {
      return pluginConfiguration.getRecordedFunctions().keySet().stream().min(Comparator.naturalOrder()).orElse(null);
    }
    if (!executionFlow.getExecutedInstructions().isEmpty()) {
      return executionFlow.getExecutedInstructions().get(0);
    }
    return null;
  }

  private long inferAddressDelta(PluginConfiguration pluginConfiguration, ExecutionFlow executionFlow) {
    SegmentedAddress runtimeEntry = findRuntimeEntry(pluginConfiguration, executionFlow);
    if (runtimeEntry == null) {
      return 0;
    }
    Address programEntry = findProgramEntryPoint();
    if (programEntry == null) {
      return 0;
    }
    return programEntry.getUnsignedOffset() - runtimeEntry.toPhysical();
  }

  private SegmentedAddress findRuntimeEntry(PluginConfiguration pluginConfiguration, ExecutionFlow executionFlow) {
    for (Map.Entry<SegmentedAddress, String> entry : pluginConfiguration.getRecordedFunctions().entrySet()) {
      if (entry.getValue().startsWith("entry_")) {
        return entry.getKey();
      }
    }
    return findSampleAddress(pluginConfiguration, executionFlow);
  }

  private Address findProgramEntryPoint() {
    AddressIterator iterator = program.getSymbolTable().getExternalEntryPointIterator();
    if (iterator.hasNext()) {
      return iterator.next();
    }
    return memory.getMinAddress();
  }

  private int importRecordedFunctions(Map<SegmentedAddress, String> recordedFunctions) {
    int imported = 0;
    for (Map.Entry<SegmentedAddress, String> entry : recordedFunctions.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
      SegmentedAddress segmentedAddress = entry.getKey();
      Address address = toProgramAddress(segmentedAddress);
      if (!memory.contains(address)) {
        log.warning("Skipping recorded function outside program memory: " + segmentedAddress);
        continue;
      }

      ensureDisassembled(address);
      Function function = listing.getFunctionAt(address);
      if (function != null) {
        maybeRenameFunction(function, entry.getValue());
      } else if (listing.getInstructionAt(address) != null) {
        try {
          functionCreator.createOrUpdateFunction(entry.getValue(), address);
        } catch (RuntimeException exception) {
          log.warning("Could not create function at " + address + ": " + exception.getMessage());
          ensureLabel(address, entry.getValue());
        }
      } else {
        ensureLabel(address, entry.getValue());
      }

      setBookmark(
          address,
          "Recorded Function",
          entry.getValue() + " at " + segmentedAddress + " imported from spice86dumpGhidraSymbols.txt"
      );
      imported++;
    }
    return imported;
  }

  private int importFlowReferences(
      Map<Integer, List<SegmentedAddress>> fromTo,
      RefType refType,
      String bookmarkCategory,
      String labelPrefix
  ) {
    int imported = 0;
    for (Map.Entry<Integer, List<SegmentedAddress>> entry : fromTo.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
      Address from = toProgramAddress(entry.getKey());
      if (!memory.contains(from)) {
        log.warning("Skipping " + bookmarkCategory + " source outside program memory: " + Utils.toHexWith0X(entry.getKey()));
        continue;
      }

      ensureDisassembled(from);
      for (SegmentedAddress target : entry.getValue()) {
        Address to = toProgramAddress(target);
        if (!memory.contains(to)) {
          log.info("Observed " + bookmarkCategory + " outside current program memory: " + target);
          continue;
        }
        ensureDisassembled(to);
        ensureAutoLabel(to, "spice86_" + labelPrefix + "_target_" + Utils.toHexSegmentOffsetPhysical(target));
        if (referenceManager.getReference(from, to, ReferenceManager.MNEMONIC) == null) {
          referenceManager.addMemoryReference(
              from,
              to,
              refType,
              SourceType.USER_DEFINED,
              ReferenceManager.MNEMONIC
          );
          imported++;
        }
        setBookmark(
            to,
            bookmarkCategory,
            "Observed " + refType + " target from " + Utils.toHexWith0X(entry.getKey())
        );
      }
    }
    return imported;
  }

  private int importReturnTargets(Map<Integer, List<SegmentedAddress>> returnTargets) {
    int imported = 0;
    for (Map.Entry<Integer, List<SegmentedAddress>> entry : returnTargets.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
      for (SegmentedAddress target : entry.getValue()) {
        Address to = toProgramAddress(target);
        if (!memory.contains(to)) {
          log.info("Observed return target outside current program memory: " + target);
          continue;
        }
        ensureDisassembled(to);
        ensureAutoLabel(to, "spice86_ret_target_" + Utils.toHexSegmentOffsetPhysical(target));
        setBookmark(
            to,
            "Return Target",
            "Observed runtime return target from " + Utils.toHexWith0X(entry.getKey())
        );
        imported++;
      }
    }
    return imported;
  }

  private int importExecutedBlocks(List<SegmentedAddress> executedInstructions) {
    List<ExecutedBlock> executedBlocks = groupExecutedBlocks(executedInstructions);
    int imported = 0;
    for (ExecutedBlock block : executedBlocks) {
      Address start = toProgramAddress(block.start());
      if (!memory.contains(start)) {
        log.info("Executed block outside current program memory: " + block.describe());
        continue;
      }

      boolean disassembled = ensureDisassembled(start);
      setBookmark(
          start,
          "Executed Block",
          block.describe()
              + ", unique starts="
              + block.size()
              + (disassembled ? "" : ", entry still not disassembled in Ghidra")
      );
      imported++;
    }
    return imported;
  }

  private int importExecutableByteWrites(Map<Integer, Map<Integer, Set<ByteModificationRecord>>> executableWrites) {
    int imported = 0;
    for (Map.Entry<Integer, Map<Integer, Set<ByteModificationRecord>>> targetEntry : executableWrites.entrySet()) {
      Address target = toProgramAddress(targetEntry.getKey());
      if (!memory.contains(target)) {
        continue;
      }
      Map<Integer, Set<ByteModificationRecord>> writers = targetEntry.getValue();
      StringBuilder comment = new StringBuilder("Executable byte modified by ");
      boolean firstWriter = true;
      for (Map.Entry<Integer, Set<ByteModificationRecord>> writerEntry : writers.entrySet()) {
        if (!firstWriter) {
          comment.append(", ");
        }
        firstWriter = false;
        comment.append(Utils.toHexWith0X(writerEntry.getKey()));
        Set<ByteModificationRecord> records = writerEntry.getValue();
        if (!records.isEmpty()) {
          ByteModificationRecord record = records.iterator().next();
          comment.append(" (")
              .append(Utils.toHexWith0X(record.getOldValue()))
              .append(" -> ")
              .append(Utils.toHexWith0X(record.getNewValue()))
              .append(")");
        }
      }
      setBookmark(target, "Executable Byte Write", comment.toString());
      imported++;
    }
    return imported;
  }

  private List<ExecutedBlock> groupExecutedBlocks(List<SegmentedAddress> executedInstructions) {
    Set<SegmentedAddress> unique = new LinkedHashSet<>(executedInstructions);
    List<SegmentedAddress> ordered = unique.stream().sorted().toList();
    if (ordered.isEmpty()) {
      return List.of();
    }

    List<ExecutedBlock> blocks = new ArrayList<>();
    SegmentedAddress blockStart = ordered.get(0);
    SegmentedAddress previous = ordered.get(0);
    int count = 1;
    for (int index = 1; index < ordered.size(); index++) {
      SegmentedAddress current = ordered.get(index);
      boolean contiguous = current.getSegment() == previous.getSegment()
          && current.toPhysical() - previous.toPhysical() <= EXECUTED_BLOCK_MAX_GAP;
      if (!contiguous) {
        blocks.add(new ExecutedBlock(blockStart, previous, count));
        blockStart = current;
        count = 1;
      } else {
        count++;
      }
      previous = current;
    }
    blocks.add(new ExecutedBlock(blockStart, previous, count));
    return blocks;
  }

  private boolean ensureDisassembled(Address address) {
    if (!memory.contains(address)) {
      return false;
    }
    if (listing.getInstructionAt(address) != null) {
      return true;
    }
    DisassembleCommand command = new DisassembleCommand(address, null, true);
    boolean result = command.applyTo(program, context.getMonitor());
    if (!result) {
      return false;
    }
    return listing.getInstructionAt(address) != null;
  }

  private void ensureLabel(Address address, String name) {
    Symbol primarySymbol = labelManager.getPrimarySymbol(address);
    if (primarySymbol != null && primarySymbol.getName().equals(name)) {
      return;
    }
    if (primarySymbol != null && !isAutoGeneratedName(primarySymbol.getName())) {
      return;
    }
    try {
      labelManager.createPrimaryLabel(address, name);
    } catch (InvalidInputException exception) {
      log.warning("Could not create label " + name + " at " + address + ": " + exception.getMessage());
    }
  }

  private void ensureAutoLabel(Address address, String name) {
    Symbol primarySymbol = labelManager.getPrimarySymbol(address);
    if (primarySymbol != null) {
      return;
    }
    try {
      labelManager.createPrimaryLabel(address, name);
    } catch (InvalidInputException exception) {
      log.warning("Could not create runtime label " + name + " at " + address + ": " + exception.getMessage());
    }
  }

  private void maybeRenameFunction(Function function, String desiredName) {
    if (function.getName().equals(desiredName)) {
      return;
    }
    if (!isAutoGeneratedName(function.getName())) {
      return;
    }
    try {
      function.setName(desiredName, SourceType.USER_DEFINED);
    } catch (DuplicateNameException | InvalidInputException exception) {
      log.warning("Could not rename function " + function.getName() + " to " + desiredName + ": "
          + exception.getMessage());
    }
  }

  private boolean isAutoGeneratedName(String name) {
    return name.startsWith("FUN_")
        || name.startsWith("LAB_")
        || name.startsWith("DAT_")
        || name.startsWith("UNK_")
        || name.startsWith("sub_")
        || name.startsWith("ghidra_guess_")
        || name.startsWith("spice86_");
  }

  private void setBookmark(Address address, String category, String comment) {
    bookmarkManager.setBookmark(address, BOOKMARK_TYPE, category, comment);
  }

  private Address toProgramAddress(SegmentedAddress segmentedAddress) {
    return toProgramAddress(segmentedAddress.toPhysical());
  }

  private Address toProgramAddress(int spice86LinearAddress) {
    return Utils.toAddr(program, spice86LinearAddress + addressDelta);
  }

  static class ImportSummary {
    int recordedFunctions;
    int callReferences;
    int jumpReferences;
    int returnTargets;
    int executedBlocks;
    int modifiedExecutableBytes;
  }

  private record ExecutedBlock(SegmentedAddress start, SegmentedAddress end, int size) {
    String describe() {
      return "Executed block " + Utils.toHexSegmentOffsetPhysical(start) + " -> "
          + Utils.toHexSegmentOffsetPhysical(end);
    }
  }
}
