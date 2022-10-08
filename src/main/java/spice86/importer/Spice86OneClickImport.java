package spice86.importer;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import spice86.tools.ExecutionFlow;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

/**
 * Imports data into ghidra from spice86 and reorganizes the code in a way the generator can work on it without too many errors
 */
public class Spice86OneClickImport {
  private PluginTool tool;
  private Program program;
  private final static Map<Integer, Integer> SEGMENTS = Map.of(
      0x1000, 0xFFFF,
      0xC000, 0xFFFF,
      0xD000, 0xFFFF,
      0xE000, 0xFFFF,
      0xF000, 0xFFFF);

  public Spice86OneClickImport(PluginTool tool, Program program) {
    this.tool = tool;
    this.program = program;
  }

  public void run() throws Exception {
    String baseFolder = System.getenv("SPICE86_DUMPS_FOLDER");
    try (Log log = new Log(tool.getService(ConsoleService.class), "OneClickImport", baseFolder + "spice86ImportLog.txt", true)) {
      log.info("Base folder is " + baseFolder);
      int transactionId = program.startTransaction("Spice86 data import");
      FunctionCreator functionCreator = new FunctionCreator(program, log);

      log.info("Reading function symbols");
      Map<SegmentedAddress, String> functions =
          new SymbolsFileReader().readFunctionFile(baseFolder + "spice86dumpGhidraSymbols.txt");

      log.info("Importing function symbols");
      new FunctionImporter(program, log, functionCreator).importFunctions(functions);

      log.info("Reading execution flow");
      ExecutionFlow executionFlow =
          readJumpMapFromFile(baseFolder + "spice86dumpExecutionFlow.json");

      log.info("Importing execution flow");
      ReferencesImporter referencesImporter = new ReferencesImporter(program, log);
      referencesImporter.importReferences(executionFlow);
      referencesImporter.disassembleEntryPoints(executionFlow, functions);

      int renames = 0;
      int splits = 0;
      int functionsWithOrphans = 0;
      int orphanRangesConvertedToFunctions = 0;
      int currentRenames = 0;
      int currentSplits = 0;
      int currentFunctionsWithOrphans = 0;
      int currentOrphanRangesConvertedToFunctions = 0;
      boolean changes;
      do {
        changes = false;
        log.info(
            "Decompiling functions to discover new code. This will take a while and even get stuck at 99% for some minutes. Don't panic.");
        EntryPointDisassembler entryPointDisassembler = new EntryPointDisassembler(program, log);
        entryPointDisassembler.decompileAllFunctions();
        log.info("Renaming functions guessed by ghidra");
        SegmentedAddressGuesser segmentedAddressGuesser = new SegmentedAddressGuesser(log, SEGMENTS);
        FunctionRenamer functionRenamer = new FunctionRenamer(program, log, segmentedAddressGuesser);
        currentRenames = functionRenamer.renameAll();
        changes |= hasChanges(log, renames, currentRenames, "Rename");

        log.info("Splitting jump functions");
        FunctionSplitter functionSplitter = new FunctionSplitter(program, log, segmentedAddressGuesser, functionCreator);
        currentSplits = functionSplitter.splitAllFunctions();
        changes |= hasChanges(log, splits, currentSplits, "Split");

        log.info("Recreating functions with potential orphans");
        OrphanedInstructionsScanner orphanedInstructionsScanner =
            new OrphanedInstructionsScanner(program, log, functionCreator, segmentedAddressGuesser);
        currentFunctionsWithOrphans = orphanedInstructionsScanner.reattachOrphans();
        changes |= hasChanges(log, functionsWithOrphans, currentFunctionsWithOrphans, "Orphan finder");
        if (!changes && functionsWithOrphans != 0) {
          log.info("There are still orphans, recreating the functions directly.");
          // No changes, but still orphans => let's create functions at orphans address ranges (this is a last resort solution but we need all instructions attached to a function)
          currentOrphanRangesConvertedToFunctions = orphanedInstructionsScanner.createFunctionsForOrphanRanges();
          changes |= hasChanges(log, orphanRangesConvertedToFunctions, currentOrphanRangesConvertedToFunctions,
              "Remaining Orphan ranges to functions");
        }

        renames = currentRenames;
        splits = currentSplits;
        functionsWithOrphans = currentFunctionsWithOrphans;
      } while (changes);
      program.endTransaction(transactionId, true);
    }
  }

  private boolean hasChanges(Log log, int previous, int now, String message) {
    if (previous != now) {
      log.info(message + " did some changes. Previous: " + previous + " now: " + now);
      return true;
    }
    return false;
  }

  private ExecutionFlow readJumpMapFromFile(String filePath) throws IOException {
    try (FileReader fileReader = new FileReader(filePath); JsonReader reader = new JsonReader(fileReader)) {
      Type type = new TypeToken<ExecutionFlow>() {
      }.getType();
      ExecutionFlow res = new Gson().fromJson(reader, type);
      res.init();
      return res;
    }
  }

}