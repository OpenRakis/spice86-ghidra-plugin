package spice86.importer;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

class OrphanedInstructionsScanner extends ObjectWithContextAndLog {
  private long minAddress = 0x0;
  private long maxAddress = 0xFFFFF;
  private Program program;
  private FunctionCreator functionCreator;
  private SegmentedAddressGuesser segmentedAddressGuesser;

  public OrphanedInstructionsScanner(Context context,
      FunctionCreator functionCreator,
      SegmentedAddressGuesser segmentedAddressGuesser) {
    super(context);
    this.program = context.getProgram();
    this.functionCreator = functionCreator;
    this.segmentedAddressGuesser = segmentedAddressGuesser;
  }

  private TreeMap<Long, Long> createFunctionRanges() {
    TreeMap<Long, Long> rangeMap = new TreeMap<>();
    List<Function> functions = Utils.getAllFunctions(program);
    for (Function function : functions) {
      AddressSetView body = function.getBody();
      for (AddressRange range : body) {
        rangeMap.put(range.getMinAddress().getUnsignedOffset(), range.getMaxAddress().getUnsignedOffset());
      }
    }
    return rangeMap;
  }

  private List<Instruction> findOrphans() {
    // Mapping functions addresses, sorted by key
    TreeMap<Long, Long> functionRanges = createFunctionRanges();
    return findOrphans(functionRanges);
  }

  private List<Instruction> findOrphans(TreeMap<Long, Long> rangeMap) {
    // reading instructions between those addresses
    List<Instruction> orphans = new ArrayList<>();
    for (long address = minAddress; address < maxAddress; ) {
      Long rangeEnd = rangeMap.get(address);
      if (rangeEnd != null) {
        // no need to browse address space inside already known functions
        address = rangeEnd + 1;
      } else {
        // address does not belong to a function
        Instruction instruction = getInstructionAt(address);
        if (instruction != null) {
          // instruction that does not belong to a function found
          orphans.add(instruction);
          address += instruction.getLength();
        } else {
          address++;
        }
      }
    }
    return orphans;
  }

  private Map<Integer, Integer> createInstructionIndexesRanges(List<Instruction> instructions) {
    Map<Integer, Integer> res = new HashMap<>();
    for (int i = 0; i < instructions.size(); ) {
      int rangeIndexStart = i;
      int rangeIndexEnd = i;
      while (isNextOrphanNextInstruction(instructions, ++i)) {
        rangeIndexEnd = i;
      }
      res.put(rangeIndexStart, rangeIndexEnd);
    }
    return res;
  }

  public int createFunctionsForOrphanRanges() throws InvalidInputException, OverlappingFunctionException {
    List<Instruction> orphans = findOrphans();
    // grouping orphans per contiguous blocks
    Map<Integer, Integer> ranges = createInstructionIndexesRanges(orphans);
    int created = 0;
    for (Map.Entry<Integer, Integer> rangeIndexes : ranges.entrySet()) {
      Instruction start = orphans.get(rangeIndexes.getKey());
      Instruction end = orphans.get(rangeIndexes.getValue());
      Address entryPoint = start.getAddress();
      Function existingFunction = program.getListing().getFunctionAt(entryPoint);
      if (existingFunction != null) {
        log.warning(
            "Found existing function " + existingFunction.getName() + " at orphan range start. Not doing anything.");
        continue;
      }
      AddressRange addressRange = new AddressRangeImpl(start.getAddress(), end.getAddress());
      SegmentedAddress segmentedAddress =
          segmentedAddressGuesser.guessSegmentedAddress((int)entryPoint.getUnsignedOffset());
      functionCreator.createFunctionWithDefinedBody(
          "orphan_range_" + Utils.toHexSegmentOffsetPhysical(segmentedAddress),
          entryPoint, addressRange);
      created++;
    }
    return created;
  }

  private void attemptReattachOrphanRanges(Map<Integer, Integer> ranges, List<Instruction> orphans) {
    for (Map.Entry<Integer, Integer> range : ranges.entrySet()) {
      int rangeIndexStart = range.getKey();
      Instruction start = orphans.get(rangeIndexStart);
      int rangeIndexEnd = range.getValue();
      Instruction end = orphans.get(rangeIndexEnd);
      String rangeDescription = toInstructionAddress(start) + " -> " + toInstructionAddress(end);
      Function function = findFirstFunctionAtOrBeforeInstruction(start);

      if (function == null) {
        log.warning("Did not find any function for range " + rangeDescription);
        continue;
      }
      String functionName = function.getName();
      log.info("Function " + functionName + " found for range " + rangeDescription + ". Attempting to re-create it.");
      functionCreator.createOrUpdateFunction(functionName, function.getEntryPoint());
    }
  }

  public int attemptReattachOrphans() {
    List<Instruction> orphans = findOrphans();
    Map<Integer, Integer> ranges = createInstructionIndexesRanges(orphans);
    attemptReattachOrphanRanges(ranges, orphans);
    log.info("Found " + orphans.size() + " orphaned instructions spanning over " + ranges.size() + " ranges.");
    return ranges.size();
  }

  private Function findFirstFunctionAtOrBeforeInstruction(Instruction instruction) {
    Instruction previous = instruction;
    while (previous != null) {
      Address address = previous.getAddress();
      Function res = program.getListing().getFunctionAt(address);
      if (res != null) {
        return res;
      }
      previous = previous.getPrevious();
    }
    return null;
  }

  private String toInstructionAddress(Instruction instruction) {
    return Utils.toHexWith0X(instruction.getAddress().getUnsignedOffset());
  }

  private boolean isNextOrphanNextInstruction(List<Instruction> orphans, int index) {
    if (index + 1 >= orphans.size()) {
      return false;
    }
    Instruction instruction = orphans.get(index);
    Instruction next = instruction.getNext();
    if (next == null) {
      return false;
    }
    Instruction nextOrphan = orphans.get(index + 1);

    return next.getAddress().getUnsignedOffset() == nextOrphan.getAddress().getUnsignedOffset();
  }

  private Instruction getInstructionAt(long address) {
    return program.getListing().getInstructionAt(Utils.toAddr(program, address));
  }
}
