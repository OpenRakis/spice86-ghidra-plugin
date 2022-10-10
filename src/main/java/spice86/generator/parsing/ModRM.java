package spice86.generator.parsing;

import com.google.gson.Gson;
import spice86.tools.Utils;

public class ModRM {
  private int mode;
  private int registerIndex;
  private int registerMemoryIndex;
  private String defaultSegment;
  private String offset;

  public ModRM(int modRM, BytesReader bytesReader) {
    mode = (modRM >> 6) & 0b11;
    registerIndex = (modRM >>> 3) & 0b111;
    registerMemoryIndex = (modRM & 0b111);
    int disp = 0;
    if (mode == 1) {
      disp = bytesReader.nextUint8();
    } else if (mode == 2) {
      disp = bytesReader.nextUint16();
    }
    if (mode == 3) {
      // value at reg[memoryRegisterIndex] to be used instead of memoryAddress
      return;
    }
    boolean bpForRm6 = mode != 0;
    defaultSegment = computeDefaultSegment(bpForRm6);
    offset = computeOffset(bytesReader, bpForRm6, disp);
  }

  private String computeDefaultSegment(boolean bpForRm6) {
    // The default segment register is SS for the effective addresses containing a
    // BP index, DS for other effective addresses
    return switch (registerMemoryIndex) {
      case 0, 1, 4, 5, 7 -> "DS";
      case 2, 3 -> "SS";
      case 6 -> bpForRm6 ? "SS" : "DS";
      default -> null;
    };
  }

  private String computeOffset(BytesReader bytesReader, boolean bpForRm6, int disp) {
    String dispString = disp == 0 ? "" : " + " + Utils.toHexWith0X(disp);
    return switch (registerMemoryIndex) {
      case 0 -> "BX + SI" + dispString;
      case 1 -> "BX + DI" + dispString;
      case 2 -> "BP + SI" + dispString;
      case 3 -> "BP + DI" + dispString;
      case 4 -> "SI" + dispString;
      case 5 -> "DI" + dispString;
      case 6 -> bpForRm6 ? "BP" + dispString : Utils.toHexWith0X(bytesReader.nextUint16() + disp);
      case 7 -> "BX" + dispString;
      default -> null;
    };
  }

  public String getDefaultSegment() {
    return defaultSegment;
  }

  @Override public String toString() {
    return new Gson().toJson(this);
  }
}
