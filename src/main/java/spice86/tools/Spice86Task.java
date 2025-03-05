package spice86.tools;

import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import spice86.tools.config.PluginConfiguration;
import spice86.tools.config.reader.PluginConfigurationReader;

import java.nio.file.Files;
import java.nio.file.Path;

public abstract class Spice86Task extends Task {
  private static final String SPICE86_DUMPS_FOLDER_ENVIRONMENT_VARIABLE = "SPICE86_DUMPS_FOLDER";
  protected ConsoleService consoleService;
  protected Program program;
  private final String logServiceName;

  public Spice86Task(String title, String logServiceName, ConsoleService consoleService, Program program) {
    super(title);
    this.consoleService = consoleService;
    this.program = program;
    this.logServiceName = logServiceName;
  }

  protected abstract void runWithContextAndConfiguration(Context context, PluginConfiguration pluginConfiguration)
      throws Exception;

  @Override public void run(TaskMonitor monitor) {
    String baseFolder = getBaseFolderIfExists();
    if (baseFolder == null) {
      return;
    }
    try (Log log = new Log(consoleService, logServiceName, baseFolder + logServiceName + ".txt")) {
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

  private String getBaseFolderIfExists() {
    String baseFolder = System.getenv(SPICE86_DUMPS_FOLDER_ENVIRONMENT_VARIABLE);
    if (baseFolder == null) {
      logErrorOrThrowExceptionIfNoLogger(
          SPICE86_DUMPS_FOLDER_ENVIRONMENT_VARIABLE + " environment variable is not set");
      return null;
    }
    if (!baseFolder.endsWith("/")) {
      baseFolder += "/";
    }
    if (baseFolder.contains("~")) {
      baseFolder = baseFolder.replace("~", System.getProperty("user.home"));
    }
    if (!Files.exists(Path.of(baseFolder))) {
      logErrorOrThrowExceptionIfNoLogger(" folder " + baseFolder + " does not exist");
      return null;
    }
    return baseFolder;
  }

  private void logErrorOrThrowExceptionIfNoLogger(String message) {
    if (consoleService == null) {
      throw new IllegalArgumentException(message);
    }
    consoleService.addErrorMessage(logServiceName, message);
  }

  protected void logAndMonitorPass(Context context, int pass, String message) {
    logAndMonitor(context, "Pass " + pass + ": " + message);
  }

  protected void logAndMonitor(Context context, String message) {
    context.getLog().info(message);
    context.getMonitor().setMessage(message);
  }
}
