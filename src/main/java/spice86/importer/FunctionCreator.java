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
    Function function = program.getListing().getFunctionContaining(address);
    if (function != null) {
      log.info("Found function " + function.getName() + " containing address " + address + ". Deleting it.");
      program.getFunctionManager().removeFunction(function.getEntryPoint());
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
    ghidra.program.model.listing.CodeUnit cu = program.getListing().getCodeUnitAt(entryPoint);
    String cuType = cu == null ? "null" : cu.getClass().getSimpleName();
    log.info("Creating function at " + entryPoint + " (" + name + "). CodeUnit at address: " + cuType);

    // Ensure the memory block is executable
    ghidra.program.model.mem.MemoryBlock block = program.getMemory().getBlock(entryPoint);
    if (block != null && !block.isExecute()) {
      log.info("Memory block " + block.getName() + " is not executable. Setting execute permission.");
      block.setExecute(true);
    }
    
    // Check if the address is valid and has code. If not, create a memory block for it.
    if (!program.getMemory().contains(entryPoint)) {
      log.info("Address " + entryPoint + " is not in memory. Attempting to create a missing segment.");
      try {
        long offset = entryPoint.getOffset();
        // Align to paragraph (16 bytes) which is standard for x86 real mode segments
        long segmentStart = (offset / 0x10) * 0x10;
        Address start = entryPoint.getNewAddress(segmentStart);
        String blockName = "spice86_auto_segment_" + Long.toHexString(segmentStart);
        // Create a smaller 4KB block instead of 64KB to be less invasive
        program.getMemory().createUninitializedBlock(blockName, start, 0x1000, false);
        log.info("Created missing memory block (paragraph aligned): " + blockName + " at " + start);
      } catch (Exception e) {
        String errorMsg = "Failed to create missing memory block at " + entryPoint + ": " + e.getMessage();
        log.error(errorMsg);
        throw new RuntimeException(errorMsg);
      }
    }
    
    String errorMessage = runCreateFunctionCommand(entryPoint, name, program.getListing().getFunctionAt(entryPoint) != null);
    if (errorMessage != null) {
      // Final desperate attempt: use listing directly
      try {
        log.info("CreateFunctionCmd failed. Attempting direct listing.createFunction at " + entryPoint);
        program.getListing().createFunction(name, entryPoint, new AddressSet(entryPoint), SourceType.USER_DEFINED);
        markFunctionAsReturning(entryPoint);
        return;
      } catch (Exception e) {
        String fullErrorMsg = "Failed to create function at " + entryPoint + ": " + errorMessage + ". Direct attempt also failed: " + e.getMessage();
        log.error(fullErrorMsg);
        throw new RuntimeException(fullErrorMsg);
      }
    }
    markFunctionAsReturning(entryPoint);
  }

  private void markFunctionAsReturning(Address entryPoint) {
    Function function = program.getListing().getFunctionAt(entryPoint);
    if (function != null) {
      function.setNoReturn(false);
    }
  }

  private String runCreateFunctionCommand(Address entryPoint, String name, boolean recreate) {
    // First attempt: Let Ghidra find the body (traditional way)
    CreateFunctionCmd cmd = new CreateFunctionCmd(name, entryPoint, null, SourceType.USER_DEFINED, false, recreate);
    boolean success = cmd.applyTo(program, taskMonitor);
    if (success) {
      return null;
    }

    String statusMsg = cmd.getStatusMsg();
    log.warning("Initial function creation failed at " + entryPoint + ": " + statusMsg + ". Trying fallback with minimal body.");

    // Fallback: Create function with a 1-instruction body
    ghidra.program.model.listing.Instruction ins = program.getListing().getInstructionAt(entryPoint);
    if (ins != null) {
      try {
        AddressSet body = new AddressSet(entryPoint, entryPoint.add(ins.getLength() - 1));
        CreateFunctionCmd fallbackCmd = new CreateFunctionCmd(name, entryPoint, body, SourceType.USER_DEFINED, false, true);
        if (fallbackCmd.applyTo(program, taskMonitor)) {
          log.info("Successfully created function at " + entryPoint + " using minimal body fallback.");
          return null;
        }
        return fallbackCmd.getStatusMsg();
      } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
        return "Address out of bounds during fallback body creation";
      }
    } else {
        return statusMsg != null ? statusMsg : "No instruction at entry point and initial command failed";
    }
  }
}
