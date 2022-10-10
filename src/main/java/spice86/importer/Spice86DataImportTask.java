package spice86.importer;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import spice86.tools.Context;
import spice86.tools.LabelManager;
import spice86.tools.SegmentedAddress;
import spice86.tools.Spice86Task;
import spice86.tools.config.ExecutionFlow;
import spice86.tools.config.PluginConfiguration;

import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

/**
 * Imports data into ghidra from spice86 and reorganizes the code in a way the generator can work on it without too many errors
 */
public class Spice86DataImportTask extends Spice86Task {
  private final static Map<Integer, Integer> SEGMENTS = Map.of(
      0x1000, 0xFFFF,
      0xC000, 0xFFFF,
      0xD000, 0xFFFF,
      0xE000, 0xFFFF,
      0xF000, 0xFFFF);

  public Spice86DataImportTask(PluginTool tool, Program program) {
    super("Spice86 Data Import", "Spice86DataImport", tool, program);
  }

  @Override
  protected void runWithContextAndConfiguration(Context context, PluginConfiguration pluginConfiguration)
      throws Exception {
    Map<SegmentedAddress, String> functions = pluginConfiguration.getRecordedFunctions();
    ExecutionFlow executionFlow = pluginConfiguration.getExecutionFlow();
    int transactionId = program.startTransaction("Spice86 data import");
    LabelManager labelManager = new LabelManager(context);

    FunctionCreator functionCreator = new FunctionCreator(context, labelManager);

    logAndMonitor(context, "Importing function symbols");
    new FunctionImporter(context, functionCreator).importFunctions(functions);

    logAndMonitor(context, "Importing execution flow");
    EntryPointDisassembler entryPointDisassembler = new EntryPointDisassembler(context);
    ReferencesImporter referencesImporter = new ReferencesImporter(context, labelManager, entryPointDisassembler);
    referencesImporter.importReferences(executionFlow);

    logAndMonitor(context, "Disassembling entry points from execution flow");
    entryPointDisassembler.disassembleEntryPoints(executionFlow, functions);

    disassembleAndOrganize(context, entryPointDisassembler, functionCreator);
    program.endTransaction(transactionId, true);
  }

  private void disassembleAndOrganize(Context context, EntryPointDisassembler entryPointDisassembler,
      FunctionCreator functionCreator) throws Exception {
    int pass = 0;
    int renames = 0;
    int splits = 0;
    int functionsWithOrphans = 0;
    int orphanRangesConvertedToFunctions = 0;
    boolean changes;
    SegmentedAddressGuesser segmentedAddressGuesser = new SegmentedAddressGuesser(context, SEGMENTS);
    FunctionRenamer functionRenamer = new FunctionRenamer(context, segmentedAddressGuesser);
    FunctionSplitter functionSplitter = new FunctionSplitter(context, segmentedAddressGuesser, functionCreator);
    OrphanedInstructionsScanner orphanedInstructionsScanner =
        new OrphanedInstructionsScanner(context, functionCreator, segmentedAddressGuesser);
    do {
      pass++;
      changes = false;

      // Decompile
      logAndMonitorPass(context, pass,
          "Decompiling functions to discover new code. This will take a while and even get stuck at 99% for some minutes. Don't panic.");
      entryPointDisassembler.decompileAllFunctions();

      // Rename discoveries
      logAndMonitorPass(context, pass, "Renaming functions guessed by ghidra");
      int currentRenames = functionRenamer.renameAll();
      changes |= hasChanges(context, renames, currentRenames, pass, "Rename");
      renames = currentRenames;

      // Split
      logAndMonitorPass(context, pass, "Splitting jump functions");
      int currentSplits = functionSplitter.splitAllFunctions();
      changes |= hasChanges(context, splits, currentSplits, pass, "Split");
      splits = currentSplits;

      // Handle orphans
      logAndMonitorPass(context, pass, "Recreating functions with potential orphans");
      int currentFunctionsWithOrphans = orphanedInstructionsScanner.attemptReattachOrphans();
      changes |= hasChanges(context, functionsWithOrphans, currentFunctionsWithOrphans, pass, "Orphan finder");
      functionsWithOrphans = currentFunctionsWithOrphans;
      if (!changes && currentFunctionsWithOrphans != 0) {
        logAndMonitorPass(context, pass, "There are still orphans, recreating the functions directly.");
        // No changes, but still orphans => let's create functions at orphans address ranges (this is a last resort solution but we need all instructions attached to a function)
        int currentOrphanRangesConvertedToFunctions = orphanedInstructionsScanner.createFunctionsForOrphanRanges();
        changes |= hasChanges(context, orphanRangesConvertedToFunctions, currentOrphanRangesConvertedToFunctions, pass,
            "Remaining Orphan ranges to functions");
        orphanRangesConvertedToFunctions = currentOrphanRangesConvertedToFunctions;
      }
    } while (changes);
  }

  private boolean hasChanges(Context context, int previous, int now, int pass, String message) {
    if (previous != now) {
      logAndMonitorPass(context, pass, message + " did some changes. Previous: " + previous + " now: " + now);
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