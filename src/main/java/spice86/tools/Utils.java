package spice86.tools;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import org.apache.commons.collections4.IteratorUtils;
import spice86.importer.Spice86OneClickImport;

import java.util.List;

public class Utils {
  private static final int SEGMENT_SIZE = 0x10000;

  public static String joinLines(List<String> res) {
    return String.join("\n", res);
  }

  public static String indent(String input, int indent) {
    if (input.isEmpty()) {
      return "";
    }
    String indentString = " ".repeat(indent);
    return indentString + input.replaceAll("\n", "\n" + indentString);
  }

  public static String getType(Integer bits) {
    if (bits == null) {
      return "unknown";
    }
    if (bits == 8) {
      return "byte";
    }
    if (bits == 16) {
      return "ushort";
    }
    if (bits == 32) {
      return "uint";
    }
    return "unknown";
  }

  public static String litteralToUpperHex(String litteralString) {
    return litteralString.toUpperCase().replaceAll("0X", "0x");
  }

  public static String toHexWith0X(long addressLong) {
    return String.format("0x%X", addressLong);
  }

  public static String toHexWithout0X(long addressLong) {
    return String.format("%X", addressLong);
  }

  public static String toHexSegmentOffset(SegmentedAddress address) {
    return String.format("%04X_%04X", address.getSegment(), address.getOffset());
  }

  public static String toHexSegmentOffsetPhysical(SegmentedAddress address) {
    return String.format("%04X_%04X_%05X", address.getSegment(), address.getOffset(), address.toPhysical());
  }

  public static int parseHex(String value) {
    return Integer.parseInt(value.replaceAll("0x", ""), 16);
  }

  public static boolean isNumber(String value) {
    try {
      parseHex(value);
      return true;
    } catch (NumberFormatException nfe) {
      return false;
    }
  }

  public static int uint(int value, int bits) {
    return switch (bits) {
      case 8 -> uint8(value);
      case 16 -> uint16(value);
      default -> throw new RuntimeException("Unsupported bits number " + bits);
    };
  }

  public static int uint8(int value) {
    return value & 0xFF;
  }

  public static int uint16(int value) {
    return value & 0xFFFF;
  }

  /**
   * Sign extend value considering it is a 8 bit value
   */
  public static int int8(int value) {
    return (byte)value;
  }

  /**
   * Sign extend value considering it is a 16 bit value
   */
  public static int int16(int value) {
    return (short)value;
  }

  public static int getUint8(byte[] memory, int address) {
    return uint8(memory[address]);
  }

  public static int getUint16(byte[] memory, int address) {
    return uint16(uint8(memory[address]) | (uint8(memory[address + 1]) << 8));
  }

  public static int toAbsoluteSegment(int physicalAddress) {
    return ((physicalAddress / SEGMENT_SIZE) * SEGMENT_SIZE) >>> 4;
  }

  public static int toAbsoluteOffset(int physicalAddress) {
    return physicalAddress - (physicalAddress / SEGMENT_SIZE) * SEGMENT_SIZE;
  }

  public static SegmentedAddress extractSpice86Address(String name) {
    String[] split = name.split("_");
    if (split.length < 4) {
      return null;
    }
    try {
      return new SegmentedAddress(Utils.parseHex(split[split.length - 3]),
          Utils.parseHex(split[split.length - 2]));
    } catch (NumberFormatException nfe) {
      return null;
    }
  }

  public static String stripSegmentedAddress(String name) {
    SegmentedAddress nameSegmentedAddress = extractSpice86Address(name);
    if (nameSegmentedAddress != null) {
      return name.replaceAll("_" + Utils.toHexSegmentOffsetPhysical(nameSegmentedAddress), "");
    }
    return name;
  }

  public static List<Function> getAllFunctions(Program program) {
    return IteratorUtils.toList(getFunctionIterator(program));
  }

  public static FunctionIterator getFunctionIterator(Program program) {
    Listing listing = program.getListing();
    return listing.getFunctions(true);
  }

  public static Address toAddr(Program program, long address) {
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
  }
}
