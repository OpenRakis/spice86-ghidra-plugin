package spice86.importer;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.InvalidInputException;
import spice86.tools.ExecutionFlow;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

class ReferencesImporter {
  private Program program;
  private EntryPointDisassembler entryPointDisassembler;
  private LabelManager labelManager;

  public ReferencesImporter(Program program, Log log) {
    this.program = program;
    this.entryPointDisassembler = new EntryPointDisassembler(program, log);
    this.labelManager = new LabelManager(program, log);
  }

  public void importReferences(ExecutionFlow executionFlow) throws Exception {
    importReferences(executionFlow.getJumpsFromTo(), RefType.COMPUTED_JUMP, "jump_target");
    importReferences(executionFlow.getCallsFromTo(), RefType.COMPUTED_CALL, null);
  }

  public void disassembleEntryPoints(ExecutionFlow executionFlow, Map<SegmentedAddress, String> functions) {
    // Collect all the addresses to disassemble
    List<Integer> addresses = new ArrayList<>();
    addresses.addAll(extractEntryPointAddresses(executionFlow.getJumpsFromTo()));
    addresses.addAll(extractEntryPointAddresses(executionFlow.getCallsFromTo()));
    addresses.addAll(extractEntryPointAddresses(executionFlow.getRetsFromTo()));
    addresses.addAll(functions.keySet().stream().map(SegmentedAddress::toPhysical).toList());
    // Sort it and disassemble it so that the disassembly order is consistent accross each run.
    addresses.stream().sorted().forEach(entryPointDisassembler::disassembleEntryPoint);
  }

  private List<Integer> extractEntryPointAddresses(Map<Integer, List<SegmentedAddress>> fromTo) {
    return fromTo.values().stream().flatMap(Collection::stream).map(SegmentedAddress::toPhysical).toList();
  }

  private void importReferences(Map<Integer, List<SegmentedAddress>> fromTo, RefType refType, String labelPrefix)
      throws Exception {
    ReferenceManager referenceManager = program.getReferenceManager();
    for (Map.Entry<Integer, List<SegmentedAddress>> e : fromTo.entrySet()) {
      Address from = Utils.toAddr(program, e.getKey());
      if (referenceManager.hasReferencesFrom(from)) {
        referenceManager.removeAllReferencesFrom(from);
      }
      List<SegmentedAddress> toSegmentedAddresses = e.getValue();
      int index = 0;
      for (SegmentedAddress toSegmentedAddress : toSegmentedAddresses) {
        Address to = Utils.toAddr(program, toSegmentedAddress.toPhysical());
        referenceManager.addMemoryReference(from, to, refType, SourceType.USER_DEFINED, index);
        index++;
        Symbol symbol = labelManager.getPrimarySymbol(to);
        if (labelPrefix != null && shouldCreateLabel(symbol)) {
          String name =
              "spice86_imported_label_" + labelPrefix + "_" + Utils.toHexSegmentOffsetPhysical(toSegmentedAddress);
          labelManager.createPrimaryLabel(to, name);
        }
        entryPointDisassembler.disassembleEntryPoint(to);
      }
    }
  }



  private boolean shouldCreateLabel(Symbol existingSymbol) {
    if (existingSymbol == null) {
      return true;
    }
    if (Utils.extractSpice86Address(existingSymbol.getName()) == null) {
      return true;
    }
    if (existingSymbol.getSymbolType() == SymbolType.FUNCTION) {
      return false;
    }
    return existingSymbol.getSymbolType() != SymbolType.LABEL;
  }
}
