package spice86.generator;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedFunctionBuilder;
import spice86.generator.parsing.ParsedProgram;
import spice86.generator.parsing.ParsedProgramBuilder;
import spice86.tools.Context;
import spice86.tools.Spice86Task;
import spice86.tools.config.CodeGeneratorConfig;
import spice86.tools.config.PluginConfiguration;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.StreamSupport;

/**
 * Generates CSharp code to run on with the Spice86 emulator as a backend (https://github.com/OpenRakis/Spice86/)
 * Please define the folder with the dump data via system environment variable SPICE86_DUMPS_FOLDER
 */
public class Spice86CodeGeneratorTask extends Spice86Task {
  public Spice86CodeGeneratorTask(PluginTool tool, Program program) {
    super("Spice86 Code Generator", "Spice86CodeGenerator", tool, program);
  }

  @Override
  protected void runWithContextAndConfiguration(Context context, PluginConfiguration pluginConfiguration)
      throws Exception {
    CodeGeneratorConfig codeGeneratorConfig = pluginConfiguration.getCodeGeneratorConfig();
    Listing listing = program.getListing();
    FunctionIterator functionIterator = listing.getFunctions(true);
    ParsedFunctionBuilder parsedFunctionBuilder = new ParsedFunctionBuilder(context);
    List<ParsedFunction> parsedFunctions = StreamSupport.stream(functionIterator.spliterator(), false)
        .map(f -> parsedFunctionBuilder.createParsedFunction(f))
        .filter(Objects::nonNull)
        .sorted(Comparator.comparingInt(f -> f.getEntrySegmentedAddress().toPhysical()))
        .toList();
    ParsedProgramBuilder parsedProgramBuilder = new ParsedProgramBuilder(context);
    ParsedProgram parsedProgram =
        parsedProgramBuilder.createParsedProgram(parsedFunctions, pluginConfiguration.getExecutionFlow(),
            codeGeneratorConfig);
    context.getLog().info("Finished parsing.");
    generateProgram(context, parsedProgram, pluginConfiguration.getGeneratedCodeFile(),
        codeGeneratorConfig.getNamespace());
  }

  private static String removeFileExtension(String filename) {
    if (filename == null || filename.isEmpty()) {
      return filename;
    }
    String extPattern = "(?<!^)[.]" + (".*");
    return filename.replaceAll(extPattern, "");
  }

  private void generateProgram(Context context, ParsedProgram parsedProgram, String generatedCodeFile, String namespace)
      throws IOException {
    List<String> cSharpFilesContents = new ProgramGenerator(context, parsedProgram, namespace).outputCSharpFiles();
    for (int i = 0; i < cSharpFilesContents.size(); i++) {
      String fileName = generatedCodeFile;
      if (i != 0) {
        fileName = removeFileExtension(generatedCodeFile) + i + ".cs";
      }
      PrintWriter printWriterFunctions = new PrintWriter(new FileWriter(fileName));
      printWriterFunctions.print(cSharpFilesContents.get(i));
      printWriterFunctions.close();
    }
  }

}
