import ghidra.app.script.GhidraScript;
import spice86.generator.Spice86CodeGeneratorTask;
import spice86.importer.Spice86RuntimeEvidenceTask;

/**
 * Wrapper that runs the Spice86 import + generation flow in headless mode.
 */
public class Spice86PluginRunner extends GhidraScript {
  @Override
  protected void run() {
    new Spice86RuntimeEvidenceTask(null, currentProgram).run(this.getMonitor());
    new Spice86CodeGeneratorTask(null, currentProgram).run(this.getMonitor());
  }
}
