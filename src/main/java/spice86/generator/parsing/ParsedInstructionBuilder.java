package spice86.generator.parsing;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ParsedInstructionBuilder extends ObjectWithContextAndLog {
  private static final Set<Integer> OPCODES_ON_8_BITS = new HashSet<>(
      Arrays.asList(0x00, 0x02, 0x04, 0x08, 0x0A, 0x0C, 0x10, 0x12, 0x14, 0x18, 0x1A, 0x1C, 0x20, 0x22, 0x24, 0x27,
          0x28, 0x2A, 0x2C, 0x2F, 0x30, 0x32, 0x34, 0x37, 0x38, 0x3A, 0x3C, 0x3F, 0x6C, 0x6E, 0x70, 0x71, 0x72,
          0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x82, 0x84, 0x86, 0x88,
          0x8A, 0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xC0,
          0xC6, 0xCD, 0xD0, 0xD2, 0xD4, 0xD5, 0xD7, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE6, 0xEB, 0xEC, 0xEE, 0xF6,
          0xFE));
  private static final Set<Integer> OPCODES_ON_16_OR_32_BITS = new HashSet<>(
      Arrays.asList(0x01, 0x03, 0x05, 0x06, 0x07, 0x09, 0x0B, 0x0D, 0x0E, 0x11, 0x13, 0x15, 0x16, 0x17, 0x19, 0x1B,
          0x1D, 0x1E, 0x1F, 0x21, 0x23, 0x25, 0x29, 0x2B, 0x2D, 0x31, 0x33, 0x35, 0x39, 0x3B, 0x3D, 0x40, 0x41, 0x42,
          0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
          0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x68, 0x69, 0x6A, 0x6B, 0x6D,
          0x6F, 0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
          0x98, 0x99, 0x9A, 0x9C, 0x9D, 0xA1, 0xA3, 0xA9, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC1, 0xC7,
          0xD1, 0xD3, 0xE5, 0xE7, 0xE8, 0xE9, 0xEA, 0xED, 0xEF, 0xF7, 0xFF));

  private static final int OPERAND_SIZE_OVERRIDE_PREFIX_32 = 0x66;

  private static final Set<Integer> PREFIXES_OPCODES =
      new HashSet<>(
          Arrays.asList(0x26, 0x2E, 0x36, 0x3E, 0x64, OPERAND_SIZE_OVERRIDE_PREFIX_32, 0x65, 0xF0, 0xF2, 0xF3));

  private static final Set<Integer> OPCODES_WITH_MODRM = new HashSet<>(
      Arrays.asList(0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
          0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B, 0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B, 0x69, 0x6B,
          0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0xC0, 0xC1,
          0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xD9, 0xDD, 0xF6, 0xF7, 0xFE, 0xFF));
  private static final Set<Integer> OPCODES_WITH_DIRECT_VALUE = new HashSet<>(
      Arrays.asList(0x04, 0x05, 0x0C, 0x0D, 0x14, 0x15, 0x1C, 0x1D, 0x24, 0x25, 0x2C, 0x2D, 0x34, 0x35, 0x3C, 0x3D,
          0x68, 0x69, 0x6A, 0x6B, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
          0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x9A, 0xA0, 0xA1, 0xA2, 0xA3, 0xA8, 0xA9, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4,
          0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC6, 0xC7, 0xCA, 0xCD,
          0xD4, 0xD5, 0xDB, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xF6, 0xF7));
  private static final Set<String> MNEMONICS_MODIFIYING_SIGNIFICANT_FLAGS = new HashSet<>(
      Arrays.asList("AAA", "AAD", "AAM", "AAS", "ADC", "ADD", "AND", "CMP", "CMPSB", "CMPSW", "DAS", "DAA", "DEC",
          "DIV", "IDIV", "IMUL", "INC", "MUL", "NEG", "POPF", "RCL", "RCR", "ROL", "ROR", "SAHF", "SAR", "SBB",
          "SCASB",
          "SCASW", "SHL", "SHR", "SUB", "TEST", "XOR"));

  private static final Set<String> MNEMONICS_USING_SIGNIFICANT_FLAGS =
      new HashSet<>(Arrays.asList("ADC", "DAS", "DAA", "PUSHF", "RCL", "RCR", "SBB"));
  private static final Map<Integer, String> SEGMENT_OVERRIDES = new HashMap<>();

  private static final Map<Integer, String> CONDITIONAL_JUMPS_OPCODES = new HashMap<>();

  static {
    SEGMENT_OVERRIDES.put(0x26, "ES");
    SEGMENT_OVERRIDES.put(0x2E, "CS");
    SEGMENT_OVERRIDES.put(0x36, "SS");
    SEGMENT_OVERRIDES.put(0x3E, "DS");
    SEGMENT_OVERRIDES.put(0x64, "FS");
    SEGMENT_OVERRIDES.put(0x65, "GS");
  }

  public ParsedInstructionBuilder(Context context) {
    super(context);
  }

  public ParsedInstruction parseInstruction(Instruction instruction, SegmentedAddress instructionAddress) {
    ParsedInstruction res = new ParsedInstruction();
    res.instruction = instruction;
    res.instructionSegmentedAddress = instructionAddress;

    String mnemonicWithPrefix = instruction.getMnemonicString();
    String[] mnemonicSplit = mnemonicWithPrefix.split("\\.");
    res.mnemonic = mnemonicSplit[0];
    res.prefix = "";
    if (mnemonicSplit.length > 1) {
      res.prefix = mnemonicSplit[1];
    }
    res.modifiesSignificantFlags = MNEMONICS_MODIFIYING_SIGNIFICANT_FLAGS.contains(res.mnemonic);
    res.usesSignificantFlags = MNEMONICS_USING_SIGNIFICANT_FLAGS.contains(res.mnemonic);

    String representation = instruction.toString();
    res.parameters = representation.replaceAll(mnemonicWithPrefix, "").trim().split(",");

    byte[] bytes;
    try {
      bytes = instruction.getBytes();
      String s = "";
      for (int i = 0; i < bytes.length; i++) {
        s += String.format("%X", bytes[i]) + ", ";
      }
      log.info("Instruction at address " + instructionAddress + " / " + Utils.toHexWith0X(
          instruction.getAddress().getUnsignedOffset()) + " bytes " + s);
    } catch (MemoryAccessException e) {
      log.info("Could not read instruction, caught " + e);
      return null;
    }
    res.instructionLength = bytes.length;
    BytesReader bytesReader = new BytesReader(bytes);
    int opCodeOrPrefixIndex = 0;
    int opCode = bytesReader.nextUint8();
    while (PREFIXES_OPCODES.contains(opCode)) {
      res.prefixes.add(opCode);
      res.prefixesOffsets.add(opCodeOrPrefixIndex);
      if (SEGMENT_OVERRIDES.containsKey(opCode)) {
        res.segment = SEGMENT_OVERRIDES.get(opCode);
      }
      if (!bytesReader.hasNextUint8()) {
        log.error("Instruction has prefix opcode but no opcode");
        return null;
      }
      opCodeOrPrefixIndex = bytesReader.getIndex();
      opCode = bytesReader.nextUint8();
    }
    res.opCode = opCode;
    res.opCodeOffset = opCodeOrPrefixIndex;
    if (OPCODES_ON_8_BITS.contains(opCode)) {
      res.instructionBitLength = 8;
      res.parameter1BitLength = 8;
    } else if (OPCODES_ON_16_OR_32_BITS.contains(opCode)) {
      if (res.prefixes.contains(OPERAND_SIZE_OVERRIDE_PREFIX_32)) {
        res.instructionBitLength = 32;
        res.parameter1BitLength = 32;
      } else {
        res.instructionBitLength = 16;
        res.parameter1BitLength = 16;
      }
      if(opCode == 0x6A) {
        // Push 8 bit value sign extended
        res.parameter1BitLength = 8;
      }
    }
    if (OPCODES_WITH_MODRM.contains(opCode)) {
      res.modRmByteOffset = bytesReader.getIndex();
      res.modRmByte = bytesReader.nextUint8();
      res.modRM = new ModRM(res.modRmByte, bytesReader);
      log.info("Instruction has modrm. modrm byte is " + res.modRmByte + " interpreted as " + res.modRM);
      if (res.segment == null) {
        // Only set it if not overridden by prefix
        res.segment = res.modRM.getDefaultSegment();
      }
    }
    int remainingLength = bytesReader.remaining();
    if (bytesReader.remaining() == 0) {
      return res;
    }
    if (!OPCODES_WITH_DIRECT_VALUE.contains(opCode)) {
      log.warning("Opcode " + Utils.toHexWithout0X(opCode)
          + " is not supposed to have a direct value but instruction has trailing bytes.");
    }
    if (remainingLength == 1) {
      res.parameter1Offset = bytesReader.getIndex();
      res.parameter1 = bytesReader.nextUint8();
      res.parameter1Signed = Utils.int8(res.parameter1);
    } else if (remainingLength == 2) {
      res.parameter1Offset = bytesReader.getIndex();
      res.parameter1 = bytesReader.nextUint16();
      res.parameter1Signed = Utils.int16(res.parameter1);
    } else if (remainingLength == 4) {
      res.parameter1Offset = bytesReader.getIndex();
      res.parameter1 = bytesReader.nextUint16();
      res.parameter2Offset = bytesReader.getIndex();
      res.parameter2 = bytesReader.nextUint16();
      if (opCode == 0x83) {
        //GRP1 operations with this opcode have param2 sign extended to match param1 which is 16 bits
        res.parameter2BitLength = 8;
      } else {
        res.parameter2BitLength = res.parameter1BitLength;
      }
    } else {
      log.warning("Found " + remainingLength + " trailing bytes, not supported.");
    }
    return res;
  }

  public void completeWithSelfModifyingCodeInformation(ParsedInstruction parsedInstruction,
      Map<Integer, Set<Integer>> possibleInstructionByteValues) {
    int physicalAddress = parsedInstruction.instructionSegmentedAddress.toPhysical();
    for (int prefixOffset : parsedInstruction.prefixesOffsets) {
      if (possibleInstructionByteValues.containsKey(physicalAddress + prefixOffset)) {
        parsedInstruction.prefixModified = true;
        break;
      }
    }
    parsedInstruction.possibleOpCodes =
        completePossibleValues(parsedInstruction, possibleInstructionByteValues, parsedInstruction.opCodeOffset,
            parsedInstruction.opCode);
    parsedInstruction.possibleModRm =
        completePossibleValues(parsedInstruction, possibleInstructionByteValues, parsedInstruction.modRmByteOffset,
            parsedInstruction.modRmByte);
    parsedInstruction.parameter1Modified =
        isParameterModified(parsedInstruction, possibleInstructionByteValues, parsedInstruction.parameter1,
            parsedInstruction.parameter1BitLength, parsedInstruction.parameter1Offset);
    parsedInstruction.parameter2Modified =
        isParameterModified(parsedInstruction, possibleInstructionByteValues, parsedInstruction.parameter2,
            parsedInstruction.parameter2BitLength, parsedInstruction.parameter2Offset);
  }

  private Set<Integer> completePossibleValues(ParsedInstruction parsedInstruction,
      Map<Integer, Set<Integer>> possibleInstructionByteValues,
      Integer offset, Integer defaultValue) {
    if (offset == null || defaultValue == null) {
      return Collections.emptySet();
    }
    int physicalAddress = parsedInstruction.instructionSegmentedAddress.toPhysical();

    Set<Integer> res = possibleInstructionByteValues.get(physicalAddress + offset);
    if (res != null) {
      return res;
    }
    return new HashSet<>(Arrays.asList(defaultValue));
  }

  private boolean isParameterModified(ParsedInstruction parsedInstruction,
      Map<Integer, Set<Integer>> possibleInstructionByteValues, Integer parameter,
      Integer parameterBitLength, Integer parameterOffset) {
    if (parameter == null) {
      // No parameter, nothing to check
      return false;
    }
    int physicalAddress = parsedInstruction.instructionSegmentedAddress.toPhysical();
    int length = parameterBitLength / 8;
    for (int offset = 0; offset < length; offset++) {
      if (possibleInstructionByteValues.containsKey(physicalAddress + parameterOffset + offset)) {
        return true;
      }
    }
    return false;
  }

}
