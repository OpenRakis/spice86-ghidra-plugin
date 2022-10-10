package spice86.generator.parsing;

import spice86.tools.Utils;

public class BytesReader {
  private final byte[] bytes;
  private int index;

  public BytesReader(byte[] bytes) {
    this.bytes = bytes;
  }

  public int nextUint8() {
    return Utils.getUint8(bytes, index++);
  }

  public int nextUint16() {
    int res = Utils.getUint16(bytes, index);
    index += 2;
    return res;
  }

  public int remaining() {
    return bytes.length - index;
  }

  public boolean hasNextUint8() {
    return remaining() >= 1;
  }

  public boolean hasNextUint16() {
    return remaining() >= 2;
  }

  public int getIndex() {
    return index;
  }
}
