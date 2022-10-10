package spice86.generator.parsing;

import com.google.gson.Gson;
import ghidra.program.model.listing.Instruction;
import spice86.generator.SelfModifyingCodeHandlingStatus;
import spice86.tools.SegmentedAddress;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ParsedInstruction implements SelfModifyingCodeHandlingStatus {
  private static final Set<Integer> STRING_OPCODES_CHECKING_ZERO_FLAG =
      new HashSet<>(Arrays.asList(0xA6, 0xA7, 0xAE, 0xAF));

  private static final Map<Integer, String> CONDITIONAL_JUMPS_OPCODES = new HashMap<>();

  static {
    CONDITIONAL_JUMPS_OPCODES.put(0x70, "O");
    CONDITIONAL_JUMPS_OPCODES.put(0x71, "NO");
    CONDITIONAL_JUMPS_OPCODES.put(0x72, "B");
    CONDITIONAL_JUMPS_OPCODES.put(0x73, "NB");
    CONDITIONAL_JUMPS_OPCODES.put(0x74, "Z");
    CONDITIONAL_JUMPS_OPCODES.put(0x75, "NZ");
    CONDITIONAL_JUMPS_OPCODES.put(0x76, "BE");
    CONDITIONAL_JUMPS_OPCODES.put(0x77, "A");
    CONDITIONAL_JUMPS_OPCODES.put(0x78, "S");
    CONDITIONAL_JUMPS_OPCODES.put(0x79, "NS");
    CONDITIONAL_JUMPS_OPCODES.put(0x7A, "P");
    CONDITIONAL_JUMPS_OPCODES.put(0x7B, "PO");
    CONDITIONAL_JUMPS_OPCODES.put(0x7C, "L");
    CONDITIONAL_JUMPS_OPCODES.put(0x7D, "GE");
    CONDITIONAL_JUMPS_OPCODES.put(0x7E, "NG");
    CONDITIONAL_JUMPS_OPCODES.put(0x7F, "G");
    CONDITIONAL_JUMPS_OPCODES.put(0xE3, "CXZ");
  }

  public static String opCodeToConditionalJumpCondition(int opcode) {
    return CONDITIONAL_JUMPS_OPCODES.get(opcode);
  }

  protected transient Instruction instruction;
  protected SegmentedAddress instructionSegmentedAddress;
  protected List<Integer> prefixes = new ArrayList<>();
  protected List<Integer> prefixesOffsets = new ArrayList<>();
  protected String segment;
  protected int opCode;
  protected int opCodeOffset;
  protected Integer modRmByte;
  protected Integer modRmByteOffset;

  protected ModRM modRM;
  protected Integer parameter1;
  protected Integer parameter1Signed;
  protected Integer parameter1Offset;
  protected Integer parameter1BitLength;

  // In case parameter2 is rewritten by other instructions this will not be null and point to the parameter offset
  protected Integer parameter2;
  protected Integer parameter2Offset;
  protected Integer parameter2BitLength;
  protected int instructionLength;
  protected String prefix;
  protected String mnemonic;
  protected String[] parameters;
  protected boolean modifiesSignificantFlags;

  protected boolean usesSignificantFlags;

  protected boolean prefixModified;
  protected Set<Integer> possibleOpCodes;
  protected Set<Integer> possibleModRm;
  protected boolean parameter1Modified;
  protected boolean parameter2Modified;

  public String getMnemonic() {
    return mnemonic;
  }

  public String getPrefix() {
    return prefix;
  }

  public String[] getParameters() {
    return parameters;
  }

  public boolean isModifiesSignificantFlags() {
    return modifiesSignificantFlags;
  }

  public boolean isUsesSignificantFlags() {
    return usesSignificantFlags;
  }

  public Instruction getInstruction() {
    return instruction;
  }

  public SegmentedAddress getNextInstructionSegmentedAddress() {
    return new SegmentedAddress(instructionSegmentedAddress.getSegment(),
        instructionSegmentedAddress.getOffset() + this.getInstructionLength());
  }

  public SegmentedAddress getInstructionSegmentedAddress() {
    return instructionSegmentedAddress;
  }

  public Integer getParameter1BitLength() {
    return parameter1BitLength;
  }

  public Integer getParameter2BitLength() {
    return parameter2BitLength;
  }

  public List<Integer> getPrefixes() {
    return prefixes;
  }

  public String getSegment() {
    return segment;
  }

  public int getOpCode() {
    return opCode;
  }

  public Integer getModRmByte() {
    return modRmByte;
  }

  public ModRM getModRM() {
    return modRM;
  }

  public Integer getParameter1() {
    return parameter1;
  }

  public Integer getParameter1Offset() {
    return parameter1Offset;
  }

  public Integer getParameter1Signed() {
    return parameter1Signed;
  }

  public Integer getParameter2() {
    return parameter2;
  }

  public Integer getParameter2Offset() {
    return parameter2Offset;
  }

  public int getInstructionLength() {
    return instructionLength;
  }

  public boolean isPrefixModified() {
    return prefixModified;
  }

  @Override
  public boolean isOpCodeModified() {
    return possibleOpCodes.size() > 1;
  }

  public Set<Integer> getPossibleOpCodes() {
    return possibleOpCodes;
  }

  public int getOpCodeOffset() {
    return opCodeOffset;
  }

  @Override
  public boolean isModRmModified() {
    return possibleModRm.size() > 1;
  }

  @Override
  public boolean isParameter1Modified() {
    return parameter1Modified;
  }

  @Override
  public boolean isParameter2Modified() {
    return parameter2Modified;
  }

  public boolean isStringCheckingZeroFlag() {
    return STRING_OPCODES_CHECKING_ZERO_FLAG.contains(opCode);
  }

  public boolean isUnconditionalJump() {
    return mnemonic.startsWith("JMP");
  }

  public boolean isRet() {
    return mnemonic.startsWith("RET");
  }

  public boolean isHlt() {
    return mnemonic.startsWith("HLT");
  }

  @Override public String toString() {
    return new Gson().toJson(this);
  }
}
