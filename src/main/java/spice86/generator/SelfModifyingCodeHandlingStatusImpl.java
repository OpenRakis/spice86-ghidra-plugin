package spice86.generator;

import com.google.gson.Gson;

public class SelfModifyingCodeHandlingStatusImpl implements SelfModifyingCodeHandlingStatus {
  private boolean opCodeModified;
  private boolean parameter1Modified;
  private boolean parameter2Modified;
  private boolean modRmModified;
  private boolean prefixModified;

  @Override public boolean isOpCodeModified() {
    return opCodeModified;
  }

  public void setOpCodeModified(boolean opCodeModified) {
    this.opCodeModified = opCodeModified;
  }

  @Override public boolean isParameter1Modified() {
    return parameter1Modified;
  }

  public void setParameter1Modified(boolean parameter1Modified) {
    this.parameter1Modified = parameter1Modified;
  }

  @Override public boolean isParameter2Modified() {
    return parameter2Modified;
  }

  public void setParameter2Modified(boolean parameter2Modified) {
    this.parameter2Modified = parameter2Modified;
  }

  @Override public boolean isModRmModified() {
    return modRmModified;
  }

  public void setModRmModified(boolean modRmModified) {
    this.modRmModified = modRmModified;
  }

  @Override public boolean isPrefixModified() {
    return prefixModified;
  }

  public void setPrefixModified(boolean prefixModified) {
    this.prefixModified = prefixModified;
  }

  @Override public String toString() {
    return new Gson().toJson(this);
  }
}
