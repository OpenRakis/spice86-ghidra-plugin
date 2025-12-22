package spice86.importer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;
import spice86.tools.config.ExecutionFlow;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

class EntryPointDisassembler extends ObjectWithContextAndLog {
  private Program program;
  private TaskMonitor taskMonitor;

  public EntryPointDisassembler(Context context) {
    super(context);
    this.program = context.getProgram();
    this.taskMonitor = context.getMonitor();
  }

  public void disassembleEntryPoints(ExecutionFlow executionFlow, Map<SegmentedAddress, String> functions) {
    // Collect all the addresses to disassemble
    List<Integer> addresses = new ArrayList<>();
    addresses.addAll(extractEntryPointAddresses(executionFlow.getJumpsFromTo()));
    addresses.addAll(extractEntryPointAddresses(executionFlow.getCallsFromTo()));
    addresses.addAll(extractEntryPointAddresses(executionFlow.getRetsFromTo()));
    addresses.addAll(functions.keySet().stream().map(SegmentedAddress::toPhysical).toList());
    // Sort it and disassemble it so that the disassembly order is consistent accross each run.
    addresses.stream().sorted().forEach(this::disassembleEntryPoint);
  }

  private List<Integer> extractEntryPointAddresses(Map<Integer, List<SegmentedAddress>> fromTo) {
    return fromTo.values().stream().flatMap(Collection::stream).map(SegmentedAddress::toPhysical).toList();
  }

  private void disassembleEntryPoint(Integer address) {
    Address ghidraAddress = Utils.toAddr(program, address);
    disassembleEntryPoint(ghidraAddress);
  }

  public void disassembleEntryPoint(Address address) {
    if (program.getListing().getInstructionAt(address) != null) {
      // Already disassembled
      log.info("No need to disassemble " + address);
      return;
    }

    // Clear any existing data or conflicting functions at this address
    ghidra.program.model.listing.CodeUnit cu = program.getListing().getCodeUnitAt(address);
    if (cu != null && !(cu instanceof ghidra.program.model.listing.Instruction)) {
      log.info("Clearing existing data at " + address + " to allow disassembly");
      program.getListing().clearCodeUnits(address, address, false);
    }

    // Check for overlapping functions that aren't starting here
    ghidra.program.model.listing.Function overlapping = program.getListing().getFunctionContaining(address);
    if (overlapping != null && !overlapping.getEntryPoint().equals(address)) {
      log.info("Address " + address + " is inside function " + overlapping.getName() + ". Clearing that function to allow new function creation.");
      program.getFunctionManager().removeFunction(overlapping.getEntryPoint());
    }

    DisassembleCommand disassembleCommand = new DisassembleCommand(address, null, true);
    boolean result = disassembleCommand.applyTo(program, taskMonitor);
    if (!result) {
      log.warning("Disassembly failed for " + address + ": " + disassembleCommand.getStatusMsg());
    } else {
      log.info("Disassembly successful for " + address);
    }
  }

  public void decompileAllFunctions() throws Exception {
    DecompilerCallback<Void> callback =
        new DecompilerCallback<Void>(program,
            new BasicDecompilerConfigurer(program)) {
          @Override
          public Void process(DecompileResults results, TaskMonitor tMonitor)
              throws Exception {
            return null;
          }
        };
    List<Function> functions = Utils.getAllFunctions(program);
    ParallelDecompiler.decompileFunctions(callback, functions, taskMonitor);
  }
}
