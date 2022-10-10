package spice86.importer;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import spice86.tools.Context;
import spice86.tools.LabelManager;
import spice86.tools.ObjectWithContextAndLog;

class FunctionCreator extends ObjectWithContextAndLog {
  private Program program;
  private TaskMonitor taskMonitor;
  private LabelManager labelManager;

  public FunctionCreator(Context context, LabelManager labelManager) {
    super(context);
    this.program = context.getProgram();
    this.taskMonitor = context.getMonitor();
    this.labelManager = labelManager;
  }

  public void removeSymbolAt(Address address) {
    labelManager.deleteAllLabels(address);
  }

  public void removeFunctionAt(Address address) {
    Function function = program.getListing().getFunctionAt(address);
    if (function != null) {
      log.info("Found function " + function.getName() + " at address " + address + ". Deleting it.");
      new DeleteFunctionCmd(function.getEntryPoint()).applyTo(this.program);
    }
  }

  public void createFunctionWithDefinedBody(String name, Address entryPoint, AddressRange addressRange)
      throws InvalidInputException, OverlappingFunctionException {
    Listing listing = program.getListing();
    AddressSetView newBody = new AddressSet(addressRange);
    log.info(
        "Creating function with entry point " + entryPoint + " with name " + name + " with range " + addressRange);
    listing.createFunction(name, entryPoint, newBody, SourceType.USER_DEFINED);
    markFunctionAsReturning(entryPoint);
  }

  public void createOrUpdateFunction(String name, Address entryPoint) {
    boolean existing = program.getListing().getFunctionAt(entryPoint) != null;
    if (existing) {
      log.info("Re-creating function at address " + entryPoint + " with name " + name);
    } else {
      log.info("Creating function at address " + entryPoint + " with name " + name);
    }
    if (!runCreateFunctionCommand(entryPoint, name, existing)) {
      throw new RuntimeException("Failed to create function at " + entryPoint);
    }
    markFunctionAsReturning(entryPoint);
  }

  private void markFunctionAsReturning(Address entryPoint) {
    Function function = program.getListing().getFunctionAt(entryPoint);
    function.setNoReturn(false);
  }

  private boolean runCreateFunctionCommand(Address entryPoint, String name, boolean recreate) {
    CreateFunctionCmd cmd = new CreateFunctionCmd(name, entryPoint, null, SourceType.USER_DEFINED, false, recreate);
    return cmd.applyTo(program, taskMonitor);
  }
}
