package spice86.tools.config.reader;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.config.CodeGeneratorConfig;
import spice86.tools.config.ExecutionFlow;
import spice86.tools.config.PluginConfiguration;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;

public class PluginConfigurationReader extends ObjectWithContextAndLog {
  public PluginConfigurationReader(Context context) {
    super(context);
  }

  public PluginConfiguration readPluginConfiguration(String generatedCodeDestination, String executionFlowFile,
      String codeGeneratorConfigFile, String symbolsFile)
      throws IOException {
    return new PluginConfiguration(
        generatedCodeDestination,
        this.readExecutionFlowFromFile(executionFlowFile),
        this.readCodeGeneratorConfigFromFile(codeGeneratorConfigFile),
        new SymbolsFileReader(context).readFunctionFile(symbolsFile)
    );
  }

  private ExecutionFlow readExecutionFlowFromFile(String filePath) throws IOException {
    log.info("Reading execution flow");
    try (FileReader fileReader = new FileReader(filePath); JsonReader reader = new JsonReader(fileReader)) {
      Type type = new TypeToken<ExecutionFlow>() {
      }.getType();
      ExecutionFlow res = new Gson().fromJson(reader, type);
      res.init();
      return res;
    }
  }

  private CodeGeneratorConfig readCodeGeneratorConfigFromFile(String filePath) throws IOException {
    log.info("Reading code generator configuration file");
    try (FileReader fileReader = new FileReader(filePath); JsonReader reader = new JsonReader(fileReader)) {
      Type type = new TypeToken<CodeGeneratorConfig>() {
      }.getType();
      CodeGeneratorConfig res = new Gson().fromJson(reader, type);
      return res;
    }
  }
}
