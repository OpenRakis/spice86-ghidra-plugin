package spice86.importer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import spice86.tools.Log;
import spice86.tools.Utils;

import java.util.List;

class EntryPointDisassembler {
  private Program program;
  private Log log;

  public EntryPointDisassembler(Program program, Log log) {
    this.program = program;
    this.log = log;
  }

  public void disassembleEntryPoint(Integer address) {
    Address ghidraAddress = Utils.toAddr(program, address);
    disassembleEntryPoint(ghidraAddress);
  }

  public void disassembleEntryPoint(Address address) {
    if (program.getListing().getInstructionAt(address) != null) {
      // Already disassembled
      log.info("No need to disassemble " + address);
      return;
    }
    DisassembleCommand disassembleCommand = new DisassembleCommand(address, null, true);
    boolean result = disassembleCommand.applyTo(program, TaskMonitor.DUMMY);
    log.info("Disassembly status for " + address + ": " + (result ? "success" : "failure"));
  }

  public void decompileAllFunctions() throws Exception {
    DecompilerCallback<Void> callback =
        new DecompilerCallback<Void>(program,
            new BasicConfigurer(program)) {
          @Override
          public Void process(DecompileResults results, TaskMonitor tMonitor)
              throws Exception {
            return null;
          }
        };
    List<Function> functions = Utils.getAllFunctions(program);
    ParallelDecompiler.decompileFunctions(callback, functions, TaskMonitor.DUMMY);
  }
}
