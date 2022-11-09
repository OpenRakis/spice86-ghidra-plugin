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
import spice86.importer.Spice86DataImportTask;

import javax.swing.ImageIcon;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.MISC,
    shortDescription = "Spice86 Ghidra integration",
    description = "Imports data from Spice86 and generates C#",
    servicesRequired = { ProgramManager.class }
)
//@formatter:on
public class Spice86Plugin extends ProgramPlugin {
  private DockingAction importAction;
  private DockingAction generateCSharpAction;

  public Spice86Plugin(PluginTool tool) {
    super(tool, false, false);
  }

  @Override
  protected void init() {
    super.init();
    importAction = createAction("Import Action", "/images/re.png", "Import runtime data", this::importData);
    tool.addAction(importAction);
    generateCSharpAction =
        createAction("C# Generation Action", "/images/csharp.png", "Generate C#", this::generateCSharp);
    tool.addAction(generateCSharpAction);
  }

  @Override
  protected void dispose() {
    if (importAction != null) {
      tool.removeAction(importAction);
    }
    if (generateCSharpAction != null) {
      tool.removeAction(generateCSharpAction);
    }
    super.dispose();
  }

  @Override
  public void programActivated(Program activatedProgram) {
    importAction.setEnabled(true);
    generateCSharpAction.setEnabled(true);
  }

  @Override
  public void programDeactivated(Program deactivatedProgram) {
    if (currentProgram == deactivatedProgram) {
      importAction.setEnabled(false);
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

  public void importData() {
    runTask(new Spice86DataImportTask(getConsoleService(), currentProgram));
  }

  public void generateCSharp() {
    runTask(new Spice86CodeGeneratorTask(getConsoleService(), currentProgram));
  }

  private ConsoleService getConsoleService() {
    return tool.getService(ConsoleService.class);
  }
}