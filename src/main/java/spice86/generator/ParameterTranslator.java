package spice86.generator;

import spice86.generator.parsing.ParsedInstruction;
import spice86.tools.Context;
import spice86.tools.InvalidBitLengthException;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.Utils;

import java.util.Map;
import java.util.Set;

public class ParameterTranslator extends ObjectWithContextAndLog {
  private final ParsedInstruction parsedInstruction;
  private final RegisterHandler registerHandler;
  private Set<String> missingRegisters;
  // variables must be unique accross a function
  private Set<String> generatedTempVars;
  private Map<Integer, String> codeSegmentVariables;

  public ParameterTranslator(Context context, ParsedInstruction parsedInstruction, RegisterHandler registerHandler,
      Map<Integer, String> codeSegmentVariables, Set<String> generatedTempVars) {
    super(context);
    this.parsedInstruction = parsedInstruction;
    this.registerHandler = registerHandler;
    this.codeSegmentVariables = codeSegmentVariables;
    this.generatedTempVars = generatedTempVars;
  }

  public Set<String> getGeneratedTempVars() {
    return generatedTempVars;
  }

  public void setMissingRegisters(Set<String> missingRegisters) {
    this.missingRegisters = missingRegisters;
  }

  public String toSpice86Value(String param, Integer bits, int offset) {
    if (Utils.isNumber(param)) {
      // Convert to unsigned (ghidra loves signed)
      int uintValue = Utils.uint(Utils.parseHex16(param), bits);
      return Utils.toHexWith0X(uintValue);
    }
    if (param.length() == 2 || param.length() == 3) {
      // register
      return registerHandler.substituteRegister(param);
    }
    if (param.startsWith("byte ptr ")) {
      return toSpice86Pointer(param.replaceAll("byte ptr ", ""), 8, offset);
    }
    if (param.startsWith("word ptr ")) {
      return toSpice86Pointer(param.replaceAll("word ptr ", ""), 16, offset);
    }
    if (param.startsWith("dword ptr ")) {
      return toSpice86Pointer(param.replaceAll("dword ptr ", ""), 32, offset);
    }
    if (bits != null) {
      return toSpice86Pointer(param, bits, offset);
    }
    log.error("Could not translate value " + param);
    return null;
  }

  public String toSpice86ValueFromModifiedParameter(String currentValue, int parameterValue, int parameterOffset,
      Integer bits, int offset) {
    String staticValueTranslated = toSpice86Value(currentValue, bits, offset);
    String staticLiteral = Utils.toHexWith0X(parameterValue);
    if (!staticValueTranslated.contains(staticLiteral)) {
      log.error(
          "This is weird, expected parameter to contain " + staticLiteral + " but value is " + staticValueTranslated);
    }
    String replacement = toInstructionParameterPointer(parameterOffset, bits);
    return staticValueTranslated.replace(staticLiteral, replacement);
  }

  public String toInstructionParameterPointer(int parameterOffset, Integer bits) {
    int offset = parsedInstruction.getInstructionSegmentedAddress().getOffset() + parameterOffset;
    String offsetExpression = "CS:" + Utils.toHexWith0X(offset);
    log.info(
        "Instruction at address " + Utils.toHexSegmentOffsetPhysical(
            parsedInstruction.getInstructionSegmentedAddress())
            + " is modified by the program at runtime. Read value from memory at " + offsetExpression
            + " rather than taking the direct value");
    return toSpice86Value(offsetExpression, bits);
  }

  public String toSpice86Value(String param, Integer bits) {
    return toSpice86Value(param, bits, 0);
  }

  public String toSpice86Pointer(String param, int bits, int offset) {
    String[] split = param.split(":");
    if (split.length == 2) {
      return toSpice86Pointer(split[0], split[1], bits, offset);
    } else {
      String segmentRegister = getSegmentRegister(param);
      return toSpice86Pointer(segmentRegister, param, bits, offset);
    }
  }

  private String getSegmentRegister(String expression) {
    String[] split = expression.split(":");
    if (split.length == 2) {
      return split[0];
    }
    if (parsedInstruction.getSegment() != null) {
      return parsedInstruction.getSegment();
    }
    if (!missingRegisters.isEmpty()) {
      String source = " ";
      if (parsedInstruction.getModRmByte() != null) {
        source = "from modrm";
      }
      if (!parsedInstruction.getPrefixes().isEmpty()) {
        source = "from prefixes";
      }
      if (missingRegisters.size() > 1) {
        log.warning("More than one missing registers, heuristic will probably not work!!!");
      }
      String res = missingRegisters.iterator().next();
      log.info("Cannot guess segment register " + source + "for parameter " + expression
          + " defaulting to missing registers heuristic. Found " + res);
      return res;
    }
    log.warning("Cannot guess segment register for parameter " + expression);
    return "DS";
  }

  public String generateSpice86OpcodePointer() {
    int opcodeOffset =
        parsedInstruction.getInstructionSegmentedAddress().getOffset() + parsedInstruction.getOpCodeOffset();
    return toSpice86Pointer("CS", Utils.toHexWith0X(opcodeOffset), 8, 0);
  }

  private String toSpice86Pointer(String segmentRegister, String offsetString, int bits, int offset) {
    String offsetExpression = toOffsetExpression(offsetString, offset);
    return toSpice86Pointer(registerHandler.substituteRegister(segmentRegister), offsetExpression, bits);
  }

  public String toCsIpPointerValueInMemoryFromModifiedParameter(String expression, int parameterValue,
      int parameterOffset) {
    String ip = toSpice86ValueFromModifiedParameter(expression, parameterValue, parameterOffset, 16, 0);
    String cs = toSpice86ValueFromModifiedParameter(expression, parameterValue, parameterOffset, 16, 2);
    return toPhysicalAddress(cs, ip);
  }

  public String toIpPointerValueInMemoryFromModifiedParameter(String expression, int parameterValue,
      int parameterOffset) {
    String ip = toSpice86ValueFromModifiedParameter(expression, parameterValue, parameterOffset, 16, 0);
    return toPhysicalAddress("CS", ip);
  }

  public String toCsIpPointerValueInMemory(String expression) {
    String ip = toSpice86Value(expression, 16, 0);
    String cs = toSpice86Value(expression, 16, 2);
    return toPhysicalAddress(cs, ip);
  }

  public String toIpPointerValueInMemory(String expression) {
    String ip = toSpice86Value(expression, 16, 0);
    return toPhysicalAddress("CS", ip);
  }

  public String toPhysicalAddress(String segmentExpression, String offsetExpression) {
    String segmentVariable = segmentExpression;
    if ("CS".equals(segmentExpression)) {
      segmentVariable = codeSegmentVariables.get(parsedInstruction.getInstructionSegmentedAddress().getSegment());
    }
    return segmentVariable + " * 0x10 + " + offsetExpression;
  }

  public String toOffsetExpression(String offsetString, int offset) {
    String offsetExpression = pointerExpressionToOffset(offsetString);
    if (offset != 0) {
      if (isDirectValue(offsetExpression)) {
        // Do the addition directly at generation time
        int value = Utils.parseHex16(offsetExpression) + offset;
        offsetExpression = Utils.toHexWith0X(value);
      } else {
        offsetExpression += " + " + offset;
      }
    }
    return castToUnsignedInt(offsetExpression, 16);
  }

  public String signExtendByteToUInt(String expression, int bits) {
    if (isDirectValue(expression)) {
      // Do the sign extension directly here to avoid confusing C#
      long value;
      if (bits == 16) {
        value = Utils.uint16(Utils.int16(Utils.parseHex16(expression)));
      } else if (bits == 32) {
        value = Utils.uint32(Utils.int32(Utils.parseHex32(expression)));
      } else {
        throw new InvalidBitLengthException(bits);
      }
      return Utils.toHexWith0X(value);
    }
    return castToUnsignedInt(castToSignedInt("(sbyte)" + expression, bits), bits);
  }

  public String castToUnsignedInt(String expression, int bits) {
    if (Utils.isNumber(expression)) {
      // No cast needed for sure.
      return expression;
    }
    String type = toUnsignedType(bits);
    return "(" + type + ")(" + expression + ")";
  }

  public String toUnsignedType(int bits) {
    if (bits == 8) {
      return "byte";
    } else if (bits == 16) {
      return "ushort";
    } else if (bits == 32) {
      return "uint";
    } else if (bits == 64) {
      return "ulong";
    } else {
      throw new InvalidBitLengthException(bits);
    }
  }

  public String toSignedType(int bits) {
    if (bits == 8) {
      return "sbyte";
    } else if (bits == 16) {
      return "short";
    } else if (bits == 32) {
      return "int";
    } else if (bits == 64) {
      return "long";
    } else {
      throw new InvalidBitLengthException(bits);
    }
  }

  public String castToSignedInt(String expression, int bits) {
    String type = toSignedType(bits);
    return "(" + type + ")(" + expression + ")";
  }

  public boolean isDirectValue(String expression) {
    if (expression.startsWith("0x") || expression.startsWith("-0x")) {
      try {
        Utils.parseHex16(expression);
        return true;
      } catch (NumberFormatException nfe) {
        return false;
      }
    }
    return false;
  }

  private String toSpice86Pointer(String segment, String offset, int bits) {
    return "UInt" + bits + "[" + segment + ", " + offset + "]";
  }

  private String pointerExpressionToOffset(String pointerString) {
    String res = Utils.litteralToUpperHex(
        pointerString.replaceAll("\\[", "")
            .replaceAll("]", "")
            .replaceAll(" \\+ 0x0", "")
            .replaceAll(" \\+ -", " - "));
    return registerHandler.substituteRegistersWithSpice86Expression(res);
  }

  private String generateNonUniqueTempVar(String prefix) {
    return prefix + Utils.toHexSegmentOffset(this.parsedInstruction.getInstructionSegmentedAddress());
  }

  public String generateTempVar(String prefix) {
    String res = generateNonUniqueTempVar(prefix);
    int index = 1;
    while (generatedTempVars.contains(res)) {
      index++;
      log.info("Variable already in scope of function, adding index " + res);
      res = generateNonUniqueTempVar(prefix + index + "_");
    }
    generatedTempVars.add(res);
    return res;
  }

  public String generateTempVar() {
    return generateTempVar("tmp_");
  }

  public String regIndexToReg(int regIndex) {
    return switch (regIndex) {
      case 0 -> "AX";
      case 1 -> "CX";
      case 2 -> "DX";
      case 3 -> "BX";
      case 4 -> "SP";
      case 5 -> "BP";
      case 6 -> "SI";
      case 7 -> "DI";
      default -> throw new RuntimeException("Unsupported regindex " + regIndex);
    };
  }

  public String generateAssignmentWithType(String type, String left, String right) {
    return type + " " + generateAssignment(left, right);
  }

  public String generateAssignment(String left, String right) {
    return left + " = " + right + ";";
  }
}
