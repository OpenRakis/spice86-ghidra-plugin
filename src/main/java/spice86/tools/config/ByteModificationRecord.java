package spice86.tools.config;

import com.google.gson.annotations.SerializedName;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class ByteModificationRecord {
  @SerializedName("OldValue") private int oldValue;

  @SerializedName("NewValue") private int newValue;

  public int getOldValue() {
    return oldValue;
  }

  public int getNewValue() {
    return newValue;
  }

  @Override public boolean equals(Object o) {
    return this == o
        || o instanceof ByteModificationRecord that && this.oldValue == that.oldValue
        && this.newValue == that.newValue;
  }

  @Override public int hashCode() {
    return new HashCodeBuilder().append(oldValue).append(newValue).toHashCode();
  }
}
