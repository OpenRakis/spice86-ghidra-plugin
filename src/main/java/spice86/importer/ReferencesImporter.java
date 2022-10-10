package spice86.importer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import spice86.tools.Context;
import spice86.tools.LabelManager;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;
import spice86.tools.config.ExecutionFlow;

import java.util.List;
import java.util.Map;

class ReferencesImporter {
  private Program program;
  private LabelManager labelManager;
  private EntryPointDisassembler entryPointDisassembler;

  public ReferencesImporter(Context context, LabelManager labelManager, EntryPointDisassembler entryPointDisassembler) {
    this.program = context.getProgram();
    this.labelManager = labelManager;
    this.entryPointDisassembler = entryPointDisassembler;
  }

  public void importReferences(ExecutionFlow executionFlow) throws Exception {
    importReferences(executionFlow.getJumpsFromTo(), RefType.COMPUTED_JUMP, "jump_target");
    importReferences(executionFlow.getCallsFromTo(), RefType.COMPUTED_CALL, null);
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
