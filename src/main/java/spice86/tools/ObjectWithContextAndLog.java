package spice86.tools;

public class ObjectWithContextAndLog {
  protected Context context;
  protected Log log;

  public ObjectWithContextAndLog(Context context) {
    this.context = context;
    this.log = context.getLog();
  }
}
