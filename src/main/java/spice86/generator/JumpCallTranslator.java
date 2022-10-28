package spice86.generator;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedInstruction;
import spice86.generator.parsing.ParsedProgram;
import spice86.tools.Context;
import spice86.tools.LabelManager;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class JumpCallTranslator {
  private final Log log;
  private final Context context;
  private final ParsedProgram parsedProgram;
  private final ParameterTranslator parameterTranslator;
  private final ParsedInstruction parsedInstruction;
  private final SegmentedAddress instructionSegmentedAddress;
  private final ParsedFunction currentFunction;
  private SelfModifyingCodeHandlingStatusImpl selfModifyingCodeHandlingStatus =
      new SelfModifyingCodeHandlingStatusImpl();

  public JumpCallTranslator(Context context, ParameterTranslator parameterTranslator,
      ParsedProgram parsedProgram, ParsedFunction currentFunction, ParsedInstruction parsedInstruction) {
    this.context = context;
    this.log = context.getLog();
    this.parsedProgram = parsedProgram;
    this.currentFunction = currentFunction;
    this.parameterTranslator = parameterTranslator;
    this.parsedInstruction = parsedInstruction;
    this.instructionSegmentedAddress = parsedInstruction.getInstructionSegmentedAddress();
  }

  public SelfModifyingCodeHandlingStatusImpl getSelfModifyingCodeHandlingStatus() {
    return selfModifyingCodeHandlingStatus;
  }

  public String getLabel() {
    if (hasGhidraLabel() || this.parsedProgram.getExecutionFlow()
        .getJumpTargets()
        .contains(this.instructionSegmentedAddress)) {
      return getLabelToAddress(this.instructionSegmentedAddress, true) + "\n";
    }
    return "";
  }

  private boolean hasGhidraLabel() {
    Address address = Utils.toAddr(context.getProgram(), this.instructionSegmentedAddress.toPhysical());
    Symbol label = new LabelManager(context).getPrimarySymbol(address);
    return label != null && (label.getSymbolType() == SymbolType.LABEL
        || label.getSymbolType() == SymbolType.FUNCTION);
  }

  public static String getLabelToAddress(SegmentedAddress address, boolean colon) {
    String colonString = colon ? ":" : "";
    return "label_" + Utils.toHexSegmentOffsetPhysical(address) + colonString;
  }

  private String generateJumpCondition(String condition) {
    if (parsedInstruction.isOpCodeModified()) {
      return generateJumpConditionForModifiedOpcode();
    }
    return generateJumpConditionForUnmodifiedOpcode(condition);
  }

  private String generateJumpConditionForModifiedOpcode() {
    String opcodePointer = parameterTranslator.generateSpice86OpcodePointer();
    Set<Integer> possibleOpcodes = parsedInstruction.getPossibleOpCodes();
    List<String> conditions = new ArrayList<>();
    boolean allOpcodesHandled = true;
    for (int opcode : possibleOpcodes) {
      String conditionCode = parsedInstruction.opCodeToConditionalJumpCondition(opcode);
      if (conditionCode == null) {
        log.info("Unhandled opcode for conditional jumps " + Utils.toHexWith0X(opcode));
        allOpcodesHandled = false;
        continue;
      }
      String conditionOnOpcode = opcodePointer + "==" + Utils.toHexWith0X(opcode);
      String conditionForOpCode =
          generateJumpConditionForUnmodifiedOpcode(conditionCode);
      String condition = "(" + conditionOnOpcode + " && " + conditionForOpCode + ")";
      conditions.add(condition);
    }
    this.selfModifyingCodeHandlingStatus.setOpCodeModified(allOpcodesHandled);
    return String.join(" || ", conditions);
  }

  private String generateJumpConditionForUnmodifiedOpcode(String condition) {
    return switch (condition) {
      case "A" -> "!CarryFlag && !ZeroFlag";
      case "BE" -> "CarryFlag || ZeroFlag";
      case "C" -> "CarryFlag";
      case "CXZ" -> "CX == 0";
      case "G" -> "!ZeroFlag && SignFlag == OverflowFlag";
      case "GE" -> "SignFlag == OverflowFlag";
      case "L" -> "SignFlag != OverflowFlag";
      case "LE" -> "ZeroFlag || SignFlag != OverflowFlag";
      case "NC" -> "!CarryFlag";
      case "NO" -> "!OverflowFlag";
      case "NS" -> "!SignFlag";
      case "NP" -> "!ParityFlag";
      case "NZ" -> "!ZeroFlag";
      case "O" -> "OverflowFlag";
      case "S" -> "SignFlag";
      case "P" -> "ParityFlag";
      case "Z" -> "ZeroFlag";
      default -> "UNHANDLED CONDITION " + condition;
    };
  }

  public String generateJump(String condition, String param, boolean far) {
    if (!condition.isEmpty()) {
      String res = "if(" + generateJumpCondition(condition) + ") {\n";
      res += Utils.indent(generateJump(param, far), 2) + "\n";
      res += "}";
      return res;
    }
    return generateJump(param, far);
  }

  private List<SegmentedAddress> getTargetsOfJumpCall() {
    return this.parsedProgram.getExecutionFlow()
        .getCallsJumpsFromTo()
        .get(this.instructionSegmentedAddress.toPhysical());
  }

  public String generateJump(String param, boolean far) {
    if (!param.startsWith("0x")) {
      String target = toPointerValueInMemory(param, far);
      return generateIndirectJump(param, target);
    }
    if (parsedInstruction.isAnyParameterModified()) {
      // Direct address but parameters are modified
      String target = readJumpCallTargetFromModifiedInstruction(far);
      return generateIndirectJump("location specified by self modifying instruction", target);
    }
    SegmentedAddress target = readJumpCallTargetFromInstruction(far);
    log.info("Jump target is " + target);
    return generateGoto(target);
  }

  private String generateIndirectJump(String param, String spice86Target) {
    // Indirect address ...
    List<SegmentedAddress> targets = getTargetsOfJumpCall();
    List<String> res = new ArrayList<>();
    res.add("// Indirect jump to " + param + ", generating possible targets from emulator records");
    res.add(generateSwitchToIndirectTarget(spice86Target, targets, "Error: Jump not registered at address ",
        this::jumpToCaseBody));
    return Utils.joinLines(res);
  }

  private String readJumpCallTargetFromModifiedInstruction(boolean far) {
    selfModifyingCodeHandlingStatus.setParameter1Modified(parsedInstruction.isParameter1Modified());
    if (far) {
      String segment =
          toInstructionParameter(parsedInstruction.isParameter2Modified(), parsedInstruction.getParameter2(),
              parsedInstruction.getParameter2Offset());
      String offset =
          toInstructionParameter(parsedInstruction.isParameter1Modified(), parsedInstruction.getParameter1(),
              parsedInstruction.getParameter1Offset());
      selfModifyingCodeHandlingStatus.setParameter2Modified(parsedInstruction.isParameter2Modified());
      return parameterTranslator.toPhysicalAddress(segment, offset);
    }
    // instruction length needed because offset is from the next instruction
    int baseOffset = instructionSegmentedAddress.getOffset() + parsedInstruction.getInstructionLength();
    String offsetPointer =
        toInstructionParameter(true, parsedInstruction.getParameter1(), parsedInstruction.getParameter1Offset());
    String offset = parameterTranslator.castToUInt(Utils.toHexWith0X(baseOffset) + " + " + offsetPointer, 16);
    return parameterTranslator.toPhysicalAddress("CS", offset);
  }

  private String toInstructionParameter(boolean isModified, int value, int offset) {
    if (isModified) {
      return parameterTranslator.toInstructionParameterPointer(offset, 16);
    }
    return Utils.toHexWith0X(value);
  }

  private SegmentedAddress readJumpCallTargetFromInstruction(boolean far) {
    // Generating jump target from instruction bytes and not from ghidra listing as it doesn't work well for multiple segments.
    if (far) {
      return new SegmentedAddress(parsedInstruction.getParameter2(), parsedInstruction.getParameter1());
    } else {
      // instruction length needed because offset is from the next instruction
      int instructionLength = parsedInstruction.getInstructionLength();
      int targetSegment = instructionSegmentedAddress.getSegment();
      Integer signedOffset = parsedInstruction.getParameter1Signed();
      if (signedOffset == null) {
        log.info("Error: expected a signed offset for instruction " + parsedInstruction);
      }
      int targetOffset = Utils.uint16(instructionSegmentedAddress.getOffset() + instructionLength + signedOffset);
      return new SegmentedAddress(targetSegment, targetOffset);
    }
  }

  private String jumpToCaseBody(SegmentedAddress address) {
    String res = generateGoto(address);
    if (res.startsWith("goto label_")) {
      res += "\nbreak;";
    }
    return res;
  }

  private String attemptConvertJumpToFunctionCall(ParsedFunction function, Integer internalJumpAddress) {
    String nonEntry = internalJumpAddress == null ? "entry " : "non entry ";
    if (function == null) {
      log.info("Could not convert jump to " + nonEntry + "call because function at target is null");
    } else if (function.equals(this.currentFunction)) {
      log.info("Could not convert jump to " + nonEntry + "call because function at target is the current function "
          + function.getName());
    } else {
      if (internalJumpAddress != null) {
        log.info("Converted jump to call to address " + Utils.toHexWith0X(internalJumpAddress)
            + " corresponding to function " + function.getName());
      }
      // If a function is found, change the jump to a function call
      return "// Jump converted to " + nonEntry + "function call\n" + functionToJumpDispatcherCall(function,
          internalJumpAddress);
    }
    return null;
  }

  private String inlineJumpOrRet(ParsedInstruction instruction) {
    String mnemonic = instruction.getMnemonic();
    if (instruction.isUnconditionalJump() || instruction.isRet() || instruction.isHlt()) {
      String comment = "// " + this.parsedInstruction.getMnemonic() + " target is " + mnemonic + ", inlining.\n";
      // Giving current function because the generated instruction is going to be generated in the function we currently are at
      InstructionGenerator generator =
          new InstructionGenerator(this.context, this.parsedProgram, currentFunction, instruction,
              parameterTranslator.getGeneratedTempVars());
      return comment + generator.convertInstructionToSpice86(false);
    }
    return null;
  }

  private String generateGoto(SegmentedAddress target) {
    // check if target is a ret or another jump, and inline it if it is the case
    ParsedInstruction targetInstruction = parsedProgram.getInstructionAtSegmentedAddress(target);
    if (targetInstruction != null) {
      String inline = inlineJumpOrRet(targetInstruction);
      if (inline != null) {
        return inline;
      }
    } else {
      String label = getLabelToAddress(target, false);
      return InstructionGenerator.generateFailAsUntested(
          "Would have been a goto but label " + label
              + " does not exist because no instruction was found there that belongs to a function.", true);
    }
    String convertedCall =
        attemptConvertJumpToFunctionCall(parsedProgram.getFunctionAtSegmentedAddressEntryPoint(target), null);
    if (convertedCall != null) {
      return convertedCall;
    }
    String convertedExtraCall =
        attemptConvertJumpToFunctionCall(parsedProgram.getFunctionAtSegmentedAddressAny(target), target.toPhysical());
    if (convertedExtraCall != null) {
      return convertedExtraCall;
    }
    log.info("Converting jump to regular goto");
    return "goto " + getLabelToAddress(target, false) + ";";
  }

  public String generateCall(String param, boolean far) {
    if (!param.startsWith("0x")) {
      String target = toPointerValueInMemory(param, far);
      return generateIndirectCall(param, target, far);
    }
    if (parsedInstruction.isAnyParameterModified()) {
      // Direct address but parameters are modified
      String target = readJumpCallTargetFromModifiedInstruction(far);
      return generateIndirectCall("location specified by self modifying instruction", target, far);
    }
    SegmentedAddress target = readJumpCallTargetFromInstruction(far);
    log.info("Call target is " + target);
    ParsedFunction function = parsedProgram.getFunctionAtSegmentedAddressEntryPoint(target);
    if (function == null) {
      return noFunctionAtAddress(target);
    }
    return functionCallToString(function, far);
  }

  private String generateIndirectCall(String param, String target, boolean far) {
    // Indirect address ...
    List<SegmentedAddress> targets = getTargetsOfJumpCall();
    List<String> res = new ArrayList<>();
    res.add("// Indirect call to " + param + ", generating possible targets from emulator records");
    res.add(generateSwitchToIndirectTarget(target, targets, "Error: Function not registered at address ",
        address -> functionToCaseBody(address, far)));
    return Utils.joinLines(res);
  }

  private String functionToCaseBody(SegmentedAddress address, boolean far) {
    ParsedFunction function = parsedProgram.getFunctionAtSegmentedAddressEntryPoint(address);
    if (function == null) {
      return noFunctionAtAddress(address);
    }
    return functionCallToString(function, far) + " break;";
  }

  public String functionCallToString(ParsedFunction parsedFunction, boolean far) {
    String name = parsedFunction.getName();
    String callType = far ? "Far" : "Near";
    int segment = this.parsedInstruction.getInstructionSegmentedAddress().getSegment();
    int offset = this.parsedInstruction.getInstructionSegmentedAddress().getOffset()
        + this.parsedInstruction.getInstructionLength();

    return callType + "Call(" + parsedProgram.getCodeSegmentVariables().get(segment) + ", " + Utils.toHexWith0X(
        offset)
        + ", " + name + ");";
  }

  public String functionToDirectCSharpCallWithReturn(ParsedFunction parsedFunction, Integer internalJumpOffset) {
    String internalJumpOffsetString = toInternalJumpOffset(internalJumpOffset);
    return "return " + parsedFunction.getName() + "(" + internalJumpOffsetString + ");";
  }

  public String functionToJumpDispatcherCall(ParsedFunction parsedFunction, Integer internalJumpOffset) {
    String internalJumpOffsetString = toInternalJumpOffset(internalJumpOffset);
    String res = "if(JumpDispatcher.Jump(" + parsedFunction.getName() + ", " + internalJumpOffsetString + ")) {\n";
    res += """
          loadOffset = JumpDispatcher.NextEntryAddress;
          goto entrydispatcher;
        }
        return JumpDispatcher.JumpAsmReturn!;""";
    return res;
  }

  private String toInternalJumpOffset(Integer internalJumpOffset) {
    if (internalJumpOffset != null) {
      // Rebase the offset from the executable load address
      return Utils.toHexWith0X(internalJumpOffset) + " - cs1 * 0x10";
    }
    return "0";
  }

  private String noFunctionAtAddress(SegmentedAddress address) {
    return InstructionGenerator.generateFailAsUntested(
        "Could not find a valid function at address " + address, true);
  }

  private String toPointerValueInMemory(String expression, boolean far) {
    if (parsedInstruction.isParameter1Modified()) {
      if (far) {
        return parameterTranslator.toCsIpPointerValueInMemoryFromModifiedParameter(expression,
            parsedInstruction.getParameter1(), parsedInstruction.getParameter1Offset());
      }
      return parameterTranslator.toIpPointerValueInMemoryFromModifiedParameter(expression,
          parsedInstruction.getParameter1(), parsedInstruction.getParameter1Offset());
    }
    if (far) {
      return parameterTranslator.toCsIpPointerValueInMemory(expression);
    }
    return parameterTranslator.toIpPointerValueInMemory(expression);
  }

  private String generateSwitchToIndirectTarget(String target, List<SegmentedAddress> targets,
      String errorInCaseNotFound, java.util.function.Function<SegmentedAddress, String> toCSharp) {
    String tempVarName = parameterTranslator.generateTempVar("targetAddress_");
    if (target.contains("cs1 * 0x10")) {
      log.info("Removing exe load address from switch target address calculation " + target);
      target = target.replaceAll("cs1 \\* 0x10 \\+ ", "");
    } else {
      log.info("Subtracting exe load address from target address calculation " + target);
      target += " - cs1 * 0x10";
    }
    StringBuilder res = new StringBuilder("uint " + tempVarName + " = (uint)(" + target + ");\n");
    res.append("switch(" + tempVarName + ") {\n");
    if (targets != null) {
      for (SegmentedAddress targetFromRecord : targets) {
        String action = toCSharp.apply(targetFromRecord);
        if (action.contains("\n")) {
          action = "{\n" + Utils.indent(action, 4) + "\n  }";
        }
        String targetPhysicalRelocated =
            Utils.toHexWith0X(targetFromRecord.toPhysical() - parsedProgram.getCs1Physical());
        log.info(
            "Target " + Utils.toHexSegmentOffsetPhysical(targetFromRecord) + " becomes " + targetPhysicalRelocated
                + " when relocated " + Utils.toHexWith0X(targetFromRecord.toPhysical()) + " - " + Utils.toHexWith0X(
                parsedProgram.getCs1Physical()));
        res.append("  case " + targetPhysicalRelocated + " : " + action + "\n");
      }
    }
    String failAsUntested = InstructionGenerator.generateFailAsUntested(
        "\"" + errorInCaseNotFound + "\" + ConvertUtils.ToHex32WithoutX(" + tempVarName + ")", false);
    res.append("  default: " + failAsUntested + "\n" + "    break;\n" + "}");
    return res.toString();
  }
}
