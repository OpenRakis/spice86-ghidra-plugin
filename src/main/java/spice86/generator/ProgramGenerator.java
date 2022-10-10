package spice86.generator;

import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedProgram;
import spice86.tools.Context;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProgramGenerator {
  private final Context context;
  private final Log log;
  private final ParsedProgram parsedProgram;
  private final String namespace;
  // too many lines in one file makes C# IDEs very slow
  private static final int MAXIMUM_CHARACTERS_PER_CSHARP_FILE = 160000;

  public ProgramGenerator(Context context, ParsedProgram parsedProgram, String namespace) {
    this.context = context;
    this.log = context.getLog();
    this.parsedProgram = parsedProgram;
    this.namespace = namespace;
  }

  public List<String> outputCSharpFiles() {
    List<String> res = new ArrayList<>();
    StringBuilder fileContent = generateCSharpClassHeaderAndDefinition();
    fileContent.append(Utils.indent(generateSegmentStorage(), 2));
    fileContent.append("\n");
    fileContent.append(Utils.indent(generateConstructor(), 2));
    Collection<ParsedFunction> parsedFunctions = parsedProgram.getEntryPoints().values();
    fileContent.append(Utils.indent(generateOverrideDefinitionFunction(parsedFunctions), 2) + "\n");
    fileContent.append(Utils.indent(generateCodeRewriteDetector(), 2));
    fileContent.append('\n');
    Iterator<String> functionInterator = generateFunctions(parsedFunctions).iterator();
    if (!functionInterator.hasNext()) {
      closeFileContentAndAddToList(fileContent, res);
      return res;
    }
    while (functionInterator.hasNext()) {
      fileContent.append(functionInterator.next());
      if (!functionInterator.hasNext() || fileContent.length() >= MAXIMUM_CHARACTERS_PER_CSHARP_FILE) {
        closeFileContentAndAddToList(fileContent, res);
        fileContent = generateCSharpClassHeaderAndDefinition();
      }
    }
    return res;
  }

  private void closeFileContentAndAddToList(StringBuilder fileContent, List<String> files) {
    fileContent.append("}\n");
    files.add(fileContent.toString());
  }

  private StringBuilder generateCSharpClassHeaderAndDefinition() {
    StringBuilder additionalFile = new StringBuilder();
    additionalFile.append(generateNamespace());
    additionalFile.append(generateImports());
    additionalFile.append(generateClassDeclaration());
    additionalFile.append("\n");
    return additionalFile;
  }

  private String generateNamespace() {
    return "namespace " + namespace + ";\n\n";
  }

  private String generateImports() {
    return "";
  }

  private String generateClassDeclaration() {
    return "public partial class GeneratedOverrides : CSharpOverrideHelper {\n";
  }

  private String generateConstructor() {
    String res =
        "public GeneratedOverrides(Dictionary<SegmentedAddress, FunctionInformation> functionInformations, Machine machine, ushort entrySegment = "
            + Utils.toHexWith0X(parsedProgram.getCs1Physical() / 0x10)
            + ") : base(functionInformations, machine) {\n";
    res += Utils.indent(generateSegmentConstructorAssignment(), 2);
    res += '\n';
    res += "  DefineGeneratedCodeOverrides();\n";
    res += "  DetectCodeRewrites();\n";
    res += "  SetProvidedInterruptHandlersAsOverridden();\n";
    res += "}\n\n";
    return res;
  }

  private String generateOverrideDefinitionFunction(Collection<ParsedFunction> functions) {
    StringBuilder res = new StringBuilder("public void DefineGeneratedCodeOverrides() {\n");
    int lastSegment = 0;

    for (ParsedFunction parsedFunction : functions) {
      String name = parsedFunction.getName();
      SegmentedAddress address = parsedFunction.getEntrySegmentedAddress();
      int currentSegment = address.getSegment();
      if (currentSegment != lastSegment) {
        lastSegment = currentSegment;
        res.append("  // " + Utils.toHexWith0X(currentSegment) + "\n");
      }
      res.append(
          "  DefineFunction(" + parsedProgram.getCodeSegmentVariables().get(currentSegment) + ", "
              + Utils.toHexWith0X(
              address.getOffset()) + ", " + name + ", false);");
      res.append('\n');
    }
    res.append("}\n\n");
    return res.toString();
  }

  private String generateSegmentConstructorAssignment() {
    return "// Observed cs1 address at generation time is " + Utils.toHexWith0X(parsedProgram.getCs1Physical() / 0x10)
        + ". Do not set entrySegment to something else if the program is not relocatable.\n" + generateSegmentVars(
        e -> "this." + e.getValue() + " = (ushort)(entrySegment + " + Utils.toHexWith0X(
            e.getKey() - parsedProgram.getCs1Physical() / 0x10) + ");\n");
  }

  private String generateSegmentStorage() {
    return generateSegmentVars(
        v -> "protected ushort " + v.getValue() + "; // " + Utils.toHexWith0X(v.getKey()) + "\n");
  }

  private String generateSegmentVars(java.util.function.Function<Map.Entry<Integer, String>, String> mapper) {
    return parsedProgram.getCodeSegmentVariables()
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(Map.Entry::getValue))
        .map(mapper)
        .collect(Collectors.joining(""));
  }

  private List<String> generateFunctions(Collection<ParsedFunction> functions) {
    List<String> list = new ArrayList<>();
    for (ParsedFunction parsedFunction : functions) {
      String funcStr =
          Utils.indent(new FunctionGenerator(context, parsedProgram, parsedFunction).outputCSharp(), 2)
              + '\n';
      list.add(funcStr);
    }
    return list;
  }

  private String generateCodeRewriteDetector() {
    StringBuilder res = new StringBuilder("public void DetectCodeRewrites() {\n");
    List<Integer> codeAddresses = parsedProgram.getInstructionAddresses().stream().sorted().toList();
    if (!codeAddresses.isEmpty()) {
      int rangeStart = codeAddresses.get(0);
      for (int i = 0; i < codeAddresses.size(); i++) {
        int currentAddress = codeAddresses.get(i);
        int currentInstructionLength = parsedProgram.getInstructionAtAddress(currentAddress).getInstructionLength();
        if (i == codeAddresses.size() - 1) {
          // Last instruction
          res.append(defineExecutableArea(rangeStart, currentAddress + currentInstructionLength - 1));
        } else {
          int actualNextAddress = codeAddresses.get(i + 1);
          int expectedNextAddress = currentAddress + currentInstructionLength;
          if (expectedNextAddress != actualNextAddress) {
            // end of range
            res.append(defineExecutableArea(rangeStart, expectedNextAddress - 1));
            rangeStart = actualNextAddress;
          }
        }
      }
    }
    res.append("}\n\n");
    return res.toString();
  }

  private String defineExecutableArea(int rangeStart, int rangeEnd) {
    return "  DefineExecutableArea(" + Utils.toHexWith0X(rangeStart) + ", " + Utils.toHexWith0X(rangeEnd) + ");\n";
  }
}
