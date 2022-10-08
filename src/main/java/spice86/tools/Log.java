package spice86.tools;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;

import java.io.Closeable;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class Log implements Closeable {
  private final ConsoleService consoleService;
  private final String service;
  private final PrintWriter printWriterLogs;
  private final boolean consoleOutput;

  public Log(ConsoleService consoleService, String service, String logFile, boolean consoleOutput) throws IOException {
    this.consoleService = consoleService;
    this.service = service;
    this.printWriterLogs = new PrintWriter(new FileWriter(logFile));
    this.consoleOutput = consoleOutput;
  }

  public void info(String line) {
    log("Info: " + line);
  }

  public void warning(String line) {
    log("Warning: " + line);
  }

  public void error(String line) {
    log("Error: " + line);
  }

  private void log(String line) {
    printWriterLogs.println(line);
    if (consoleOutput) {
      consoleService.addMessage(service, line);
    }
  }

  @Override public void close() {
    printWriterLogs.close();
  }
}
