package spice86.importer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.Map;

class FunctionImporter {
  private Program program;
  private Log log;
  private FunctionCreator functionCreator;

  public FunctionImporter(Program program, Log log, FunctionCreator functionCreator) {
    this.program = program;
    this.log = log;
    this.functionCreator = functionCreator;
  }

  public void importFunctions(Map<SegmentedAddress, String> functions) {
    for (Map.Entry<SegmentedAddress, String> functionEntry : functions.entrySet()) {
      SegmentedAddress segmentedAddress = functionEntry.getKey();
      String name = functionEntry.getValue();

      Address entry = Utils.toAddr(program, segmentedAddress.toPhysical());
      log.info("Importing function at address " + entry);
      functionCreator.removeSymbolAt(entry);
      functionCreator.removeFunctionAt(entry);
      functionCreator.createOrUpdateFunction(name, entry);
    }
  }

}
