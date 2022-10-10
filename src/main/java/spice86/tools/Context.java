package spice86.tools;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class Context {
  private Log log;
  private TaskMonitor monitor;
  private Program program;

  public Context(Log log, TaskMonitor monitor, Program program) {
    this.log = log;
    this.monitor = monitor;
    this.program = program;
  }

  public Log getLog() {
    return log;
  }

  public TaskMonitor getMonitor() {
    return monitor;
  }

  public Program getProgram() {
    return program;
  }
}
