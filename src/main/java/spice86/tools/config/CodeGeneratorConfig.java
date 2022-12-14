package spice86.tools.config;

import com.google.gson.annotations.SerializedName;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CodeGeneratorConfig {
  @SerializedName("Namespace") private String namespace = "generated";
  @SerializedName("GenerateCheckExternalEventsBeforeInstruction") private Boolean
      generateCheckExternalEventsBeforeInstruction = true;
  @SerializedName("CodeToInject") private Map<String, List<String>> codeToInject = new HashMap<>();
  @SerializedName("InstructionsToReplace") private Map<String, String> instructionsToReplace = new HashMap<>();

  public String getNamespace() {
    return namespace;
  }

  public boolean isGenerateCheckExternalEventsBeforeInstruction() {
    return generateCheckExternalEventsBeforeInstruction == null ? true : generateCheckExternalEventsBeforeInstruction;
  }

  public Map<String, List<String>> getCodeToInject() {
    return codeToInject;
  }

  public Map<String, String> getInstructionsToReplace() {
    return instructionsToReplace;
  }
}
