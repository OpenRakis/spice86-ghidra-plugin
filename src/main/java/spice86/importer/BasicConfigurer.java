package spice86.importer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.program.model.listing.Program;

class BasicConfigurer implements DecompileConfigurer {
  private Program program;

  public BasicConfigurer(Program program) {
    this.program = program;
  }

  @Override
  public void configure(DecompInterface decompiler) {
    decompiler.toggleCCode(true);
    decompiler.toggleSyntaxTree(true);
    decompiler.setSimplificationStyle("decompile");
    DecompileOptions opts = new DecompileOptions();
    opts.grabFromProgram(program);
    decompiler.setOptions(opts);
  }
}
