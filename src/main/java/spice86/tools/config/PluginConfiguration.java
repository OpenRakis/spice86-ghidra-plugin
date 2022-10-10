package spice86.tools.config;

import spice86.tools.SegmentedAddress;

import java.util.Map;

public class PluginConfiguration {
  private String generatedCodeFile;
  private ExecutionFlow executionFlow;
  private CodeGeneratorConfig codeGeneratorConfig;
  private Map<SegmentedAddress, String> recordedFunctions;

  public PluginConfiguration(String generatedCodeFile, ExecutionFlow executionFlow,
      CodeGeneratorConfig codeGeneratorConfig, Map<SegmentedAddress, String> recordedFunctions) {
    this.generatedCodeFile = generatedCodeFile;
    this.executionFlow = executionFlow;
    this.codeGeneratorConfig = codeGeneratorConfig;
    this.recordedFunctions = recordedFunctions;
  }

  public String getGeneratedCodeFile() {
    return generatedCodeFile;
  }

  public ExecutionFlow getExecutionFlow() {
    return executionFlow;
  }

  public CodeGeneratorConfig getCodeGeneratorConfig() {
    return codeGeneratorConfig;
  }

  public Map<SegmentedAddress, String> getRecordedFunctions() {
    return recordedFunctions;
  }
}
