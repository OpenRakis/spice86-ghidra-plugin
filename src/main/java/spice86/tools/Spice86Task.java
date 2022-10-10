package spice86.tools;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import spice86.tools.config.PluginConfiguration;
import spice86.tools.config.reader.PluginConfigurationReader;

public abstract class Spice86Task extends Task {
  protected PluginTool tool;
  protected Program program;
  private String logServiceName;

  public Spice86Task(String title, String logServiceName, PluginTool tool, Program program) {
    super(title);
    this.tool = tool;
    this.program = program;
    this.logServiceName = logServiceName;
  }

  protected abstract void runWithContextAndConfiguration(Context context, PluginConfiguration pluginConfiguration)
      throws Exception;

  @Override public void run(TaskMonitor monitor) {
    String baseFolder = System.getenv("SPICE86_DUMPS_FOLDER");
    ConsoleService consoleService = tool.getService(ConsoleService.class);
    try (Log log = new Log(consoleService, logServiceName, baseFolder + logServiceName + ".txt", true)) {
      Context context = new Context(log, monitor, program);
      logAndMonitor(context, "Base folder is " + baseFolder);
      PluginConfigurationReader pluginConfigurationReader = new PluginConfigurationReader(context);
      PluginConfiguration pluginConfiguration = pluginConfigurationReader.readPluginConfiguration(
          baseFolder + "GeneratedCode.cs",
          baseFolder + "spice86dumpExecutionFlow.json",
          baseFolder + "CodeGeneratorConfig.json",
          baseFolder + "spice86dumpGhidraSymbols.txt");

      runWithContextAndConfiguration(context, pluginConfiguration);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected void logAndMonitorPass(Context context, int pass, String message) {
    logAndMonitor(context, "Pass " + pass + ": " + message);
  }

  protected void logAndMonitor(Context context, String message) {
    context.getLog().info(message);
    context.getMonitor().setMessage(message);
  }
}
