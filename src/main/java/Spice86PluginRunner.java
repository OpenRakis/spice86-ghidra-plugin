import ghidra.app.script.GhidraScript;
import spice86.generator.Spice86CodeGeneratorTask;
import spice86.importer.Spice86DataImportTask;

/**
 * Wrapper that runs the Spice86 plugin for ghidra headless
 */
public class Spice86PluginRunner extends GhidraScript {
  @Override
  protected void run() {
    new Spice86DataImportTask(null, currentProgram).run(this.getMonitor());
    new Spice86CodeGeneratorTask(null, currentProgram).run(this.getMonitor());
  }
}