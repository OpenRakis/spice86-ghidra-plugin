package spice86.tools;

import ghidra.app.services.ConsoleService;

import java.io.Closeable;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class Log implements Closeable {
  private final ConsoleService consoleService;
  private final String service;
  private final PrintWriter printWriterLogs;

  public Log(ConsoleService consoleService, String service, String logFile) throws IOException {
    this.consoleService = consoleService;
    this.service = service;
    this.printWriterLogs = new PrintWriter(new FileWriter(logFile));
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
    if (consoleService != null) {
      consoleService.addMessage(service, line);
    }
  }

  @Override public void close() {
    printWriterLogs.close();
  }
}
