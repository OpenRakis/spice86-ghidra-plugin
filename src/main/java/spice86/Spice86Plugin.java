package spice86;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import spice86.generator.Spice86CodeGeneratorTask;
import spice86.importer.Spice86RuntimeEvidenceTask;

import javax.swing.ImageIcon;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Spice86 runtime import and C# generation",
    description = "Imports runtime evidence from Spice86 into the current program and generates C# overrides",
    servicesRequired = { ProgramManager.class }
)
//@formatter:on
public class Spice86Plugin extends ProgramPlugin {
  private DockingAction importRuntimeEvidenceAction;
  private DockingAction generateCSharpAction;

  public Spice86Plugin(PluginTool tool) {
    super(tool);
  }

  @Override
  protected void init() {
    super.init();
    importRuntimeEvidenceAction =
        createAction("Import Runtime Evidence", "/images/re.png", "Import runtime evidence", this::importRuntimeEvidence);
    tool.addAction(importRuntimeEvidenceAction);
    generateCSharpAction =
        createAction("Generate C# Overrides", "/images/csharp.png", "Generate C#", this::generateCSharp);
    tool.addAction(generateCSharpAction);
  }

  @Override
  protected void dispose() {
    if (importRuntimeEvidenceAction != null) {
      tool.removeAction(importRuntimeEvidenceAction);
    }
    if (generateCSharpAction != null) {
      tool.removeAction(generateCSharpAction);
    }
    super.dispose();
  }

  @Override
  public void programActivated(Program activatedProgram) {
    importRuntimeEvidenceAction.setEnabled(true);
    generateCSharpAction.setEnabled(true);
  }

  @Override
  public void programDeactivated(Program deactivatedProgram) {
    if (currentProgram == deactivatedProgram) {
      importRuntimeEvidenceAction.setEnabled(false);
      generateCSharpAction.setEnabled(false);
    }
  }

  private DockingAction createAction(String name, String image, String subMenu, Runnable action) {
    DockingAction res = new DockingAction(name, getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        action.run();
      }
    };
    res.setEnabled(true);
    // Put the action in the global "Spice86" menu.
    ImageIcon icon = new ImageIcon(getClass().getResource(image));
    res.setMenuBarData(new MenuData(new String[] { "Spice86", subMenu }, icon));
    return res;
  }

  private void runTask(Task task) {
    new TaskLauncher(task, tool.getActiveComponentProvider().getComponent(), 250);
  }

  public void importRuntimeEvidence() {
    runTask(new Spice86RuntimeEvidenceTask(getConsoleService(), currentProgram));
  }

  public void generateCSharp() {
    runTask(new Spice86CodeGeneratorTask(getConsoleService(), currentProgram));
  }

  private ConsoleService getConsoleService() {
    return tool.getService(ConsoleService.class);
  }
}
