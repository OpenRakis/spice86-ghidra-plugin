package spice86;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
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
import java.util.function.Supplier;

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
    importAction = createAction("Import Action", "/images/re.png", "Import runtime data", this::createImportDataTask);
    tool.addAction(importAction);
    generateCSharpAction =
        createAction("C# Generation Action", "/images/csharp.png", "Generate C#", this::createGenerateCSharpTask);
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

  private DockingAction createAction(String name, String image, String subMenu, Supplier<Task> taskSupplier) {
    DockingAction res = new DockingAction(name, getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        Task task = taskSupplier.get();
        new TaskLauncher(task, tool.getActiveComponentProvider().getComponent(), 250);
      }
    };
    res.setEnabled(true);
    // Put the action in the global "Spice86" menu.
    ImageIcon icon = new ImageIcon(getClass().getResource(image));
    res.setMenuBarData(new MenuData(new String[] { "Spice86", subMenu }, icon));
    return res;
  }

  private Task createImportDataTask() {
    return new Spice86DataImportTask(tool, currentProgram);
  }

  private Task createGenerateCSharpTask() {
    return new Spice86CodeGeneratorTask(tool, currentProgram);
  }

}