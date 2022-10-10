package spice86.importer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.Map;

class FunctionImporter extends ObjectWithContextAndLog {
  private Program program;
  private FunctionCreator functionCreator;

  public FunctionImporter(Context context, FunctionCreator functionCreator) {
    super(context);
    this.program = context.getProgram();
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
