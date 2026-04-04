package spice86.importer;

import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import spice86.tools.Context;
import spice86.tools.Spice86Task;
import spice86.tools.config.PluginConfiguration;

public class Spice86RuntimeEvidenceTask extends Spice86Task {
  public Spice86RuntimeEvidenceTask(ConsoleService consoleService, Program program) {
    super("Spice86 Runtime Evidence Import", "Spice86RuntimeEvidence", consoleService, program);
  }

  @Override
  protected void runWithContextAndConfiguration(Context context, PluginConfiguration pluginConfiguration)
      throws Exception {
    int transactionId = program.startTransaction("Spice86 runtime evidence import");
    boolean success = false;
    try {
      RuntimeEvidenceImporter importer = new RuntimeEvidenceImporter(context);
      RuntimeEvidenceImporter.ImportSummary summary = importer.importEvidence(pluginConfiguration);
      logAndMonitor(
          context,
          "Imported runtime evidence: recordedFunctions="
              + summary.recordedFunctions
              + ", callRefs="
              + summary.callReferences
              + ", jumpRefs="
              + summary.jumpReferences
              + ", returnTargets="
              + summary.returnTargets
              + ", executedBlocks="
              + summary.executedBlocks
              + ", modifiedExecutableBytes="
              + summary.modifiedExecutableBytes
      );
      success = true;
    } finally {
      program.endTransaction(transactionId, success);
    }
  }
}
