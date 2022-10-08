package spice86.tools;

import com.google.gson.annotations.SerializedName;
import spice86.importer.Spice86OneClickImport;

public class SegmentedAddress implements Comparable<SegmentedAddress> {
  @SerializedName("Segment")
  private final int segment;
  @SerializedName("Offset")
  private final int offset;

  public SegmentedAddress(int segment, int offset) {
    this.segment = Utils.uint16(segment);
    this.offset = Utils.uint16(offset);
  }

  public int getSegment() {
    return segment;
  }

  public int getOffset() {
    return offset;
  }

  public int toPhysical() {
    return segment * 0x10 + offset;
  }

  @Override
  public int hashCode() {
    return toPhysical();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    return (obj instanceof SegmentedAddress other)
        && toPhysical() == other.toPhysical();
  }

  @Override
  public int compareTo(SegmentedAddress other) {
    return Integer.compare(this.toPhysical(), other.toPhysical());
  }

  @Override
  public String toString() {
    return Utils.toHexSegmentOffset(this) + " / " + Utils.toHexWith0X(this.toPhysical());
  }
}
