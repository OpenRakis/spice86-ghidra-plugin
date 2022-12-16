package spice86.generator.instructiongenerator;

import ghidra.program.model.listing.Instruction;
import org.apache.commons.collections4.CollectionUtils;
import spice86.generator.JumpCallTranslator;
import spice86.generator.ParameterTranslator;
import spice86.generator.RegisterHandler;
import spice86.generator.SelfModifyingCodeHandlingStatusImpl;
import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedInstruction;
import spice86.generator.parsing.ParsedProgram;
import spice86.tools.Context;
import spice86.tools.InvalidBitLengthException;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class InstructionGenerator {
  private final Log log;
  private final ParameterTranslator parameterTranslator;
  private final PopGenerator popGenerator;
  private final PushGenerator pushGenerator;
  private final RegisterHandler registerHandler;

  private final ParsedProgram parsedProgram;
  private final ParsedInstruction parsedInstruction;
  private final JumpCallTranslator jumpCallTranslator;
  private final Instruction instruction;
  private boolean isFunctionReturn;
  private boolean isGoto;

  private SelfModifyingCodeHandlingStatusImpl selfModifyingCodeHandlingStatus =
      new SelfModifyingCodeHandlingStatusImpl();

  public JumpCallTranslator getJumpCallTranslator() {
    return jumpCallTranslator;
  }

  public boolean isFunctionReturn() {
    return isFunctionReturn;
  }

  public boolean isGoto() {
    return isGoto;
  }

  public InstructionGenerator(Context context, ParsedProgram parsedProgram,
      ParsedFunction currentFunction, ParsedInstruction parsedInstruction, Set<String> generatedTempVars) {
    SegmentedAddress instructionSegmentedAddress = parsedInstruction.getInstructionSegmentedAddress();
    Map<Integer, String> codeSegmentVariables = parsedProgram.getCodeSegmentVariables();
    this.log = context.getLog();
    this.registerHandler =
        new RegisterHandler(context, codeSegmentVariables.get(instructionSegmentedAddress.getSegment()));
    this.parameterTranslator =
        new ParameterTranslator(context, parsedInstruction, registerHandler, codeSegmentVariables, generatedTempVars);
    this.parsedProgram = parsedProgram;
    this.parsedInstruction = parsedInstruction;
    this.instruction = parsedInstruction.getInstruction();
    this.jumpCallTranslator =
        new JumpCallTranslator(context, parameterTranslator, parsedProgram, currentFunction, parsedInstruction);
    this.popGenerator = new PopGenerator(parameterTranslator);
    this.pushGenerator = new PushGenerator(parameterTranslator, parsedInstruction);
  }

  public String convertInstructionToSpice86(boolean generateLabel) {
    log.info("Processing instruction " + instruction + " at address " + instruction.getAddress());

    Object[] inputObjects = instruction.getInputObjects();
    Set<String> missingRegisters =
        registerHandler.computeMissingRegisters(parsedInstruction.getMnemonic(), parsedInstruction.getParameters(),
            inputObjects);
    parameterTranslator.setMissingRegisters(missingRegisters);
    String instructionString = convertCurrentInstruction();
    isFunctionReturn = isUnconditionalReturn(instructionString);
    isGoto = instructionString.contains("goto ") && !(instructionString.contains("if(") || instructionString.contains(
        "switch("));
    instructionString = generateCodeToInject() + generateCheckExternalEventsBeforeInstruction() + instructionString;
    if (generateLabel) {
      String label = jumpCallTranslator.getLabel();
      // Label above instruction, injected code and cycle inc
      instructionString = label + instructionString;
    }
    log.info("Generated instruction " + instructionString);
    return instructionString;
  }

  private String convertCurrentInstruction() {
    SegmentedAddress address = parsedInstruction.getInstructionSegmentedAddress();
    String replacement = parsedProgram.getInstructionReplacement(address);
    if (replacement != null) {
      return replacement;
    }
    String instructionString = convertInstructionWithPrefix(parsedInstruction.getMnemonic(),
        parsedInstruction.getPrefix(),
        parsedInstruction.getParameters());
    return generateModifiedInstructionWarning() + instructionString;
  }

  private String generateCodeToInject() {
    SegmentedAddress nextInstructionAddress = parsedInstruction.getNextInstructionSegmentedAddress();
    String nextSegment = parsedProgram.getCodeSegmentVariables().get(nextInstructionAddress.getSegment());
    String nextOffset = Utils.toHexWith0X(nextInstructionAddress.getOffset());

    List<String> codeToInject = parsedProgram.getCodeToInject()
        .getCodeToInject(parsedInstruction.getInstructionSegmentedAddress(), nextSegment, nextOffset);
    if (CollectionUtils.isNotEmpty(codeToInject)) {
      return String.join("\n", codeToInject) + "\n";
    }
    return "";
  }

  private String generateCheckExternalEventsBeforeInstruction() {
    if (parsedProgram.isGenerateCheckExternalEventsBeforeInstruction()) {
      SegmentedAddress nextInstructionAddress = parsedInstruction.getNextInstructionSegmentedAddress();
      String nextSegment = parsedProgram.getCodeSegmentVariables().get(nextInstructionAddress.getSegment());
      String nextOffset = Utils.toHexWith0X(nextInstructionAddress.getOffset());
      return "CheckExternalEvents(" + nextSegment + ", " + nextOffset + ");\n";
    }
    return "";
  }

  private boolean canUseNativeOperation() {
    ParsedInstruction nextParsedInstruction = parsedProgram.getInstructionAfter(parsedInstruction);
    return nextParsedInstruction != null && nextParsedInstruction.isModifiesSignificantFlags()
        && !nextParsedInstruction.isUsesSignificantFlags();
  }

  private boolean isUnconditionalReturn(String instructionString) {
    if (!instructionString.contains("return ")) {
      return false;
    }
    if (instructionString.contains("JumpDispatcher.JumpAsmReturn")) {
      // Check return is the last statement
      return instructionString.endsWith("return JumpDispatcher.JumpAsmReturn!;");
    }
    return !(instructionString.contains("if(") || instructionString.contains("switch("));
  }

  private String convertInstructionWithPrefix(String mnemonic, String prefix, String[] params) {
    if (prefix.isEmpty()) {
      return convertInstructionWithoutPrefix(mnemonic, params);
    }
    String ret = "// " + prefix + "\n";
    ret += "while (CX != 0) {\n";
    ret += "  CX--;\n";
    ret += Utils.indent(convertInstructionWithoutPrefix(mnemonic, params), 2) + "\n";
    if (parsedInstruction.isStringCheckingZeroFlag()) {
      boolean continueZeroFlagValue = prefix.equals("REPE") || prefix.equals("REP");
      ret += "  if(ZeroFlag != " + continueZeroFlagValue + ") {\n";
      ret += "    break;\n";
      ret += "  }\n";
    }
    ret += "}";
    return ret;
  }

  private String generateAssignmentWith1Parameter(String operation, String nativeOperation, String[] parameters,
      Integer bits) {
    String dest = parameterTranslator.toSpice86Value(parameters[0], bits);
    if (canUseNativeOperation()) {
      return dest + nativeOperation + ";";
    }
    return parameterTranslator.generateAssignment(dest, operation + bits + "(" + dest + ")");
  }

  private String generateAssignmentWith2ParametersOnlyOneOperand(String operation, String[] parameters,
      Integer bits) {
    String dest = parameterTranslator.toSpice86Value(parameters[0], bits);
    String operand = parameterTranslator.toSpice86Value(parameters[1], bits);
    return parameterTranslator.generateAssignment(dest, operation + bits + "(" + operand + ")");
  }

  private String generateXor(String[] parameters) {
    if (parameters[0].equals(parameters[1]) && canUseNativeOperation()) {
      Integer bits = parsedInstruction.getParameter1BitLength();
      // this is a set to 0
      String dest = parameterTranslator.toSpice86Value(parameters[0], bits);
      return parameterTranslator.generateAssignment(dest, "0");
    }
    return generateAssignmentWith2Parameters("Alu.Xor", "^", parameters);
  }

  private String generateAssignmentWith2Parameters(String operation, String nativeOperation, String[] parameters) {
    Integer bitsParameter1 = parsedInstruction.getParameter1BitLength();
    String dest = parameterTranslator.toSpice86Value(parameters[0], bitsParameter1);
    String operand = signExtendParameter2IfNeeded(parameters);
    String res = "";
    if (nativeOperation != null) {
      String resNativeOperation = dest + " " + nativeOperation + "= " + operand + ";";
      if (canUseNativeOperation()) {
        return resNativeOperation;
      }
      res += "// " + resNativeOperation + '\n';
    }
    res += parameterTranslator.generateAssignment(dest, operation + bitsParameter1 + "(" + dest + ", " + operand + ")");
    return res;
  }

  private String generateNoAssignmentWith2Parameters(String operation, String[] parameters) {
    Integer bitsParameter1 = parsedInstruction.getParameter1BitLength();
    String dest = parameterTranslator.toSpice86Value(parameters[0], bitsParameter1);
    String operand = signExtendParameter2IfNeeded(parameters);
    return operation + bitsParameter1 + "(" + dest + ", " + operand + ");";
  }

  private String signExtendParameter2IfNeeded(String[] parameters) {
    Integer bitsParameter1 = parsedInstruction.getParameter1BitLength();
    Integer bitsParameter2 = parsedInstruction.getParameter2BitLength();
    if (bitsParameter2 == null) {
      // No parameter 2 encoded in instruction
      bitsParameter2 = bitsParameter1;
    }
    String operand;
    if (parsedInstruction.getModRM() != null && parsedInstruction.isParameter1Modified()) {
      // This means the operand needs to be taken from the instruction address
      operand = parameterTranslator.toInstructionParameterPointer(parsedInstruction.getParameter1Offset(),
          parsedInstruction.getParameter1BitLength());
      this.selfModifyingCodeHandlingStatus.setParameter1Modified(true);
    } else {
      operand = parameterTranslator.toSpice86Value(parameters[1], bitsParameter2);
    }
    if (!Objects.equals(bitsParameter1, bitsParameter2)) {
      log.info("Sign extending parameter 2");
      if (bitsParameter2 != 8) {
        log.error("Parameter 1 length is " + bitsParameter1 + " and parameter 2 is " + bitsParameter2
            + " this is unsupported.");
      }
      return parameterTranslator.signExtendByteToUInt(operand, parsedInstruction.getInstructionBitLength());
    }
    return operand;
  }

  private String generateIns(String[] parameters, int bits) {
    String destination = getDestination(parameters, bits);
    String operation = parameterTranslator.generateAssignment(destination, "Cpu.In" + bits + "(DX)");
    return generateStringOperation(operation, false, true, bits);
  }

  private String generateOuts(String[] parameters, int bits) {
    String source = getSource(parameters, bits);
    String operation = "Cpu.Out" + bits + "(DX, " + source + ");";
    return generateStringOperation(operation, true, false, bits);
  }

  private String generateScas(String[] parameters, int bits) {
    String param1 = getAXOrAL(bits);
    String param2 = getDestination(parameters, bits);
    String operation = "Alu.Sub" + bits + "(" + param1 + ", " + param2 + ");";
    return generateStringOperation(operation, false, true, bits);
  }

  private String generateStos(String[] parameters, int bits) {
    String source = getAXOrAL(bits);
    String destination = getDestination(parameters, bits);
    String operation = parameterTranslator.generateAssignment(destination, source);
    return generateStringOperation(operation, false, true, bits);
  }

  private String generateLods(String[] parameters, int bits) {
    String source = getSource(parameters, bits);
    String destination = getAXOrAL(bits);
    String operation = parameterTranslator.generateAssignment(destination, source);
    return generateStringOperation(operation, true, false, bits);
  }

  private String generateCmps(String[] parameters, int bits) {
    String param1 = getSource(parameters, bits);
    String param2 = getDestination(parameters, bits);
    String operation = "Alu.Sub" + bits + "(" + param1 + ", " + param2 + ");";
    return generateStringOperation(operation, true, true, bits);
  }

  private String generateMovs(String[] parameters, int bits) {
    String destination = getDestination(parameters, bits);
    String source = getSource(parameters, bits);
    String operation = parameterTranslator.generateAssignment(destination, source);
    return generateStringOperation(operation, true, true, bits);
  }

  private String getSource(String[] parameters, int bits) {
    return parameterTranslator.toSpice86Pointer(parameters[getSIParamIndex(parameters)], bits, 0);
  }

  private String getDestination(String[] parameters, int bits) {
    return parameterTranslator.toSpice86Pointer(parameters[getDIParamIndex(parameters)], bits, 0);
  }

  private String generateStringOperation(String operation, boolean changeSI, boolean changeDI, int bits) {
    List<String> res = new ArrayList<>();
    res.add(operation);
    if (changeSI) {
      res.add(advanceRegister("SI", bits));
    }
    if (changeDI) {
      res.add(advanceRegister("DI", bits));
    }
    return Utils.joinLines(res);
  }

  private int getSIParamIndex(String[] parameters) {
    // Parameters are reversed in ghidra listing so we need to check which one is source and which one is destination ...
    return parameters[0].contains("SI") ? 0 : 1;
  }

  private int getDIParamIndex(String[] parameters) {
    // Parameters are reversed in ghidra listing so we need to check which one is source and which one is destination ...
    return parameters[0].contains("DI") ? 0 : 1;
  }

  private String advanceRegister(String register, int bits) {
    String direction = "Direction" + bits;
    String expression = parameterTranslator.castToUnsignedInt(register + " + " + direction, 16);
    return parameterTranslator.generateAssignment(register, expression);
  }

  private String generateNot(String[] parameters, Integer bits) {
    String parameter = parameterTranslator.toSpice86Value(parameters[0], bits);
    return parameterTranslator.generateAssignment(parameter,
        parameterTranslator.castToUnsignedInt("~" + parameter, bits));
  }

  private String generateNeg(String[] parameters, Integer bits) {
    String parameter = parameterTranslator.toSpice86Value(parameters[0], bits);
    return parameterTranslator.generateAssignment(parameter, "Alu.Sub" + bits + "(0, " + parameter + ")");
  }

  private String generateLXS(String segmentRegister, String[] parameters) {
    String destinationRegister = parameterTranslator.toSpice86Value(parameters[0], 16);
    String destinationSegmentRegister = segmentRegister;
    String value1 = parameterTranslator.toSpice86Value(parameters[1], 16, 0);
    String value2 = parameterTranslator.toSpice86Value(parameters[1], 16, 2);
    // Generate destinationRegister first as it is not a segment register, so it will not be used in subsequent computations for this instruction
    return parameterTranslator.generateAssignment(destinationRegister, value1) + "\n"
        + parameterTranslator.generateAssignment(destinationSegmentRegister, value2);
  }

  private String generateLoop(String condition, String param) {
    String loopCondition = "--CX != 0";
    if (!condition.isEmpty()) {
      if ("NZ".equals(condition)) {
        loopCondition += " && !ZeroFlag";
      } else if ("Z".equals(condition)) {
        loopCondition += " && ZeroFlag";
      }
    }
    String res = "if(" + loopCondition + ") {\n";
    res += Utils.indent(jumpCallTranslator.generateJump(param, false), 2) + "\n";
    this.selfModifyingCodeHandlingStatus = jumpCallTranslator.getSelfModifyingCodeHandlingStatus();
    res += "}";
    return res;
  }

  private String generateInterrupt(String parameter) {
    return "Interrupt(" + parameter + ");";
  }

  private String getAXOrAL(int bits) {
    return (bits == 8 ? "AL" : "AX");
  }

  private String generateXlat() {
    String pointer = parameterTranslator.toSpice86Pointer("BX + AL", 8, 0);
    return "AL = " + pointer + ";";
  }

  private String generateMul(String[] parameters, Integer bits) {
    return generateGrp3ImulMul(false, bits, "Mul", parameters[0]);
  }

  private String generateIMul(String[] parameters, Integer bits) {
    if (parameters.length == 3) {
      // opcodes 0x69 and 0x6B
      String destination = parameterTranslator.toSpice86Value(parameters[0], bits);
      String operand1 = parameterTranslator.toSpice86Value(parameters[1], bits);
      String operand2 = parameterTranslator.toSpice86Value(parameters[2], bits);
      return parameterTranslator.generateAssignment(destination,
          parameterTranslator.castToUnsignedInt("Alu.Imul" + bits + "(" + operand1 + ", " + operand2 + ")", bits));
    }
    // Regular grp3 imul
    return generateGrp3ImulMul(true, bits, "Imul", parameters[0]);
  }

  private String generateGrp3ImulMul(boolean signed, int bits, String aluOperation, String parameter) {
    String opRes1 = generateImulIdivOpRes1(bits);
    String op2 = parameterTranslator.toSpice86Value(parameter, bits);
    String res2 = generateImulIdivRes2(bits);
    String opSignCast = signed ? "(" + parameterTranslator.toSignedType(bits) + ")" : "";
    String tempVar = parameterTranslator.generateTempVar("res" + aluOperation);
    int resBits = bits * 2;
    String resType = signed ? parameterTranslator.toSignedType(resBits) : parameterTranslator.toUnsignedType(resBits);
    String operation = parameterTranslator.generateAssignmentWithType(resType, tempVar,
        "Alu." + aluOperation + bits + "(" + opSignCast + opRes1 + ", " + opSignCast + op2
            + ")");
    String operationAssignment1 =
        parameterTranslator.generateAssignment(opRes1, parameterTranslator.castToUnsignedInt(tempVar, bits));
    String operationAssignment2 = parameterTranslator.generateAssignment(res2,
        parameterTranslator.castToUnsignedInt(tempVar + " >> " + bits, bits));
    return operation + '\n' + operationAssignment1 + '\n' + operationAssignment2;
  }

  private String generateGrp3IdivDiv(boolean signed, int bits, String aluOperation, String parameter) {
    int op1Bits = bits * 2;
    String op1Type = signed ? parameterTranslator.toSignedType(op1Bits) : parameterTranslator.toUnsignedType(op1Bits);
    String op1Var = parameterTranslator.generateTempVar("op1" + aluOperation);
    String op1Cast = signed ? "(" + op1Type + ")" : "";
    String op1Assignment =
        parameterTranslator.generateAssignmentWithType(op1Type, op1Var, op1Cast + generateDivIdviOp1(bits));

    String op2Type = signed ? parameterTranslator.toSignedType(bits) : parameterTranslator.toUnsignedType(bits);
    String op2Var = parameterTranslator.generateTempVar("op2" + aluOperation);
    String op2Cast = signed ? "(" + op2Type + ")" : "";
    String op2Assignment =
        parameterTranslator.generateAssignmentWithType(op2Type, op2Var,
            op2Cast + parameterTranslator.toSpice86Value(parameter, bits));

    String operationResultType = op2Type + "?";
    String operationResultVar = parameterTranslator.generateTempVar("res" + aluOperation);
    String operationAssignment = parameterTranslator.generateAssignmentWithType(operationResultType, operationResultVar,
        "Alu." + aluOperation + bits + "(" + op1Var + ", " + op2Var
            + ")");

    String nullCheckAssignment =
        "if(" + operationResultVar + " == null) {\n  " + InstructionGenerator.generateFailAsUntested("Division by 0!",
            true) + "\n}";
    String resultCast = "(" + parameterTranslator.toUnsignedType(bits) + ")";
    String quotientCast = signed ? resultCast : "";

    String quotientAssignment = parameterTranslator.generateAssignment(generateImulIdivOpRes1(bits),
        quotientCast + operationResultVar + ".Value");
    String remainderAssignment = parameterTranslator.generateAssignment(generateImulIdivRes2(bits),
        resultCast + "(" + op1Var + " % " + op2Var + ")");
    return op1Assignment + '\n' + op2Assignment + '\n' + operationAssignment + '\n' + nullCheckAssignment + '\n'
        + quotientAssignment + '\n'
        + remainderAssignment;
  }

  private String generateDivIdviOp1(int bits) {
    if (bits == 8) {
      return "AX";
    } else if (bits == 16) {
      return "(DX << 16 | AX)";
    } else if (bits == 32) {
      return "(((ulong)EDX << 32) | EAX)";
    } else {
      throw new InvalidBitLengthException(bits);
    }
  }

  private String generateImulIdivOpRes1(int bits) {
    if (bits == 8) {
      return "AL";
    } else if (bits == 16) {
      return "AX";
    } else if (bits == 32) {
      return "EAX";
    } else {
      throw new InvalidBitLengthException(bits);
    }
  }

  private String generateImulIdivRes2(int bits) {
    if (bits == 8) {
      return "AH";
    } else if (bits == 16) {
      return "DX";
    } else if (bits == 32) {
      return "EDX";
    } else {
      throw new InvalidBitLengthException(bits);
    }
  }

  private String generateDiv(String[] parameters, Integer bits) {
    return generateGrp3IdivDiv(false, bits, "Div", parameters[0]);
  }

  private String generateIDiv(String[] parameters, Integer bits) {
    return generateGrp3IdivDiv(true, bits, "IDiv", parameters[0]);
  }

  private String generateLea(String[] parameters) {
    String offset = parameterTranslator.toOffsetExpression(parameters[1], 0);
    String destination = parameterTranslator.toSpice86Value(parameters[0], 16);
    return parameterTranslator.generateAssignment(destination, offset);
  }

  private String generateCbw() {
    int instructionBitLength = parsedInstruction.getInstructionBitLength();
    String sourceRegister = instructionBitLength == 16 ? "AL" : "AX";
    String destinationRegister = instructionBitLength == 16 ? "AX" : "EAX";
    return parameterTranslator.generateAssignment(destinationRegister,
        parameterTranslator.signExtendByteToUInt(sourceRegister,
            parsedInstruction.getInstructionBitLength()));
  }

  private String generateCwd() {
    int bits = parsedInstruction.getInstructionBitLength();
    String destination;
    if (bits == 16) {
      destination = "DX";
    } else if (bits == 32) {
      destination = "EDX";
    } else {
      throw new InvalidBitLengthException(bits);
    }
    String source = "";
    if (bits == 16) {
      source = "AX>=0x8000?0xFFFF:0";
    } else if (bits == 32) {
      source = "EAX>=0x80000000?0xFFFFFFFF:0";
    }
    String expression = parameterTranslator.castToUnsignedInt(source, bits);
    return parameterTranslator.generateAssignment(destination, expression);
  }

  private String convertInstructionWithoutPrefix(String mnemonic, String[] params) {
    String instuctionAsm = mnemonic + " " + String.join(",", params);
    String instruction = convertInstructionWithoutPrefixAndComment(mnemonic, params);
    if (instruction == null) {
      log.error("Unimplemented instruction " + instuctionAsm);
      instruction = InstructionGenerator.generateFailAsUntested("Unimplemented Instruction!", true);
    }
    String address = parsedInstruction.getInstructionSegmentedAddress().toString();
    return "// " + instuctionAsm + " (" + address + ")\n" + instruction;
  }

  private String generateModifiedInstructionWarning() {
    // Writes a comment in case of autogenerated code with the instruction bytes that were modified and the addresses of the instructions that did the change
    int instructionAddress = parsedInstruction.getInstructionSegmentedAddress().toPhysical();
    Map<Set<Integer>, List<Integer>> modifiersForInstruction = new HashMap<>();
    for (int i = 0; i < parsedInstruction.getInstructionLength(); i++) {
      int address = instructionAddress + i;
      Set<Integer> modifiedBy = parsedProgram.getAddressesModifyingExecutableAddress(address);
      if (CollectionUtils.isEmpty(modifiedBy)) {
        continue;
      }
      List<Integer> modifiedAddresses = modifiersForInstruction.computeIfAbsent(modifiedBy, v -> new ArrayList<>());
      modifiedAddresses.add(i);
    }
    StringBuilder res = new StringBuilder();
    for (Map.Entry<Set<Integer>, List<Integer>> entry : modifiersForInstruction.entrySet()) {
      Set<Integer> instructionsAddresses = entry.getKey();
      List<Integer> indexes = entry.getValue();
      String indexesString = indexes.stream().map(i -> Integer.toString(i)).collect(Collectors.joining(", "));
      String instructionsAddressesString =
          instructionsAddresses.stream().map(Utils::toHexWithout0X).collect(Collectors.joining(", "));
      res.append("// Instruction bytes at index " + indexesString + " modified by those instruction(s): "
          + instructionsAddressesString + '\n');
    }
    if (this.selfModifyingCodeHandlingStatus.isAnyHandled()) {
      res.append("// Instruction is modified by code, generator handled: "
          + selfModifyingCodeHandlingStatus.generateHandledItems() + '\n');
    }
    if (!this.selfModifyingCodeHandlingStatus.isAllHandled(parsedInstruction)) {
      String requiredInstruction = parsedInstruction.generateHandledItems();
      String handledParser = selfModifyingCodeHandlingStatus.generateHandledItems();
      String possibleOpCodes = parsedInstruction.getPossibleOpCodes().stream().map(Utils::toHexWithout0X).collect(
          Collectors.joining(", "));
      log.error("Unhandled instruction modification at address " + Utils.toHexSegmentOffsetPhysical(
          parsedInstruction.getInstructionSegmentedAddress()) + ". Here is what was handled by the generator "
          + selfModifyingCodeHandlingStatus + ". Parser handled: " + handledParser + ". Instruction needed: "
          + requiredInstruction);
      res.append(generateFailAsUntested(
          "Instruction is modified by code but this is at least partially unhandled. Parser handled: " + handledParser
              + ". Instruction needed: " + requiredInstruction + ". Possible opcodes: " + possibleOpCodes
              + ". Opcode offset:" + parsedInstruction.getOpCodeOffset(), true) + '\n');
    }
    return res.toString();
  }

  private String generateMov(String[] params, Integer bits) {
    String dest = parameterTranslator.toSpice86Value(params[0], bits);
    String source = parameterTranslator.toSpice86Value(params[1], bits);
    if (parsedInstruction.isParameter1Modified()) {
      source = parameterTranslator.toSpice86ValueFromModifiedParameter(params[1], parsedInstruction.getParameter1(),
          parsedInstruction.getParameter1Offset(), bits, 0);
      this.selfModifyingCodeHandlingStatus.setParameter1Modified(true);
    }
    return parameterTranslator.generateAssignment(dest, source);
  }

  private String generateXchg(String[] params, Integer bits) {
    String var1 = parameterTranslator.toSpice86Value(params[0], bits);
    String var2 = parameterTranslator.toSpice86Value(params[1], bits);
    return parameterTranslator.generateAssignment("(" + var2 + ", " + var1 + ")", "(" + var1 + ", " + var2 + ")");
  }

  private String generateRetNear(String[] params) {
    String pops = "";
    if (params.length == 1) {
      // Need to pop some bytes
      pops = params[0];
    }
    return "return NearRet(" + pops + ");";
  }

  private String generateRetFar(String[] params) {
    String pops = "";
    if (params.length == 1) {
      // Need to pop some bytes
      pops = params[0];
    }
    return "return FarRet(" + pops + ");";
  }

  private String generateConditionalJump(String condition, String[] params, boolean far) {
    String res = jumpCallTranslator.generateJump(condition, params[0], far);
    this.selfModifyingCodeHandlingStatus = jumpCallTranslator.getSelfModifyingCodeHandlingStatus();
    return res;
  }

  public static Set<Integer> INC_OPCODES =
      new HashSet<>(Arrays.asList(0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47));
  public static Set<Integer> DEC_OPCODES =
      new HashSet<>(Arrays.asList(0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F));

  private String generateDecOrIncModifiedCode(Integer bits) {
    String opcodePointer = parameterTranslator.generateSpice86OpcodePointer();
    StringBuilder res = new StringBuilder();
    res.append("switch(" + opcodePointer + ") {\n");
    String[] dynamicParameters = new String[1];
    for (int opcode : parsedInstruction.getPossibleOpCodes()) {
      res.append("  case " + opcode + ": ");
      int regIndex = opcode & 0b111;
      dynamicParameters[0] = parameterTranslator.regIndexToReg(regIndex);
      if (INC_OPCODES.contains(opcode)) {
        res.append(generateIncStatic(dynamicParameters, bits));
      } else if (DEC_OPCODES.contains(opcode)) {
        res.append(generateDecStatic(dynamicParameters, bits));
      } else {
        res.append(generateFailAsUntested(
            "INC or DEC instruction changed to something else, this is not handled by generator", true));
      }
      res.append("break;\n");
    }
    res.append("}");
    this.selfModifyingCodeHandlingStatus.setOpCodeModified(true);
    return res.toString();
  }

  private String generateIncStatic(String[] parameters, Integer bits) {
    return generateAssignmentWith1Parameter("Alu.Inc", "++", parameters, bits);
  }

  private String generateDecStatic(String[] parameters, Integer bits) {
    return generateAssignmentWith1Parameter("Alu.Dec", "--", parameters, bits);
  }

  private String generateInc(String[] parameters, Integer bits) {
    if (parsedInstruction.isOpCodeModified()) {
      return generateDecOrIncModifiedCode(bits);
    }
    return generateIncStatic(parameters, bits);
  }

  private String generateDec(String[] parameters, Integer bits) {
    if (parsedInstruction.isOpCodeModified()) {
      return generateDecOrIncModifiedCode(bits);
    }
    return generateDecStatic(parameters, bits);
  }

  private String convertInstructionWithoutPrefixAndComment(String mnemonic, String[] params) {
    log.info("Params are " + String.join(",", params));
    Integer parameter1Bits = parsedInstruction.getParameter1BitLength();
    return switch (mnemonic) {
      case "AAA" -> "Cpu.Aaa();";
      case "AAD" -> "Cpu.Aad(" + parameterTranslator.toSpice86Value(params[0], parameter1Bits) + ");";
      case "AAM" -> "Cpu.Aam(" + parameterTranslator.toSpice86Value(params[0], parameter1Bits) + ");";
      case "AAS" -> "Cpu.Aas();";
      case "ADC" -> generateAssignmentWith2Parameters("Alu.Adc", null, params);
      case "ADD" -> generateAssignmentWith2Parameters("Alu.Add", "+", params);
      case "AND" -> generateAssignmentWith2Parameters("Alu.And", "&", params);
      case "CALL" -> jumpCallTranslator.generateCall(params[0], false);
      case "CALLF" -> jumpCallTranslator.generateCall(params[0], true);
      case "CBW" -> generateCbw();
      case "CLC" -> "CarryFlag = false;";
      case "CLD" -> "DirectionFlag = false;";
      case "CLI" -> "InterruptFlag = false;";
      case "CMC" -> "CarryFlag = !CarryFlag;";
      case "CMP" -> generateNoAssignmentWith2Parameters("Alu.Sub", params);
      case "CMPSB" -> generateCmps(params, 8);
      case "CMPSW" -> generateCmps(params, 16);
      case "CWD" -> generateCwd();
      case "DAS" -> "Cpu.Das();";
      case "DAA" -> "Cpu.Daa();";
      case "DEC" -> generateDec(params, parameter1Bits);
      case "DIV" -> generateDiv(params, parameter1Bits);
      case "HLT" -> "return Hlt();";
      case "IDIV" -> generateIDiv(params, parameter1Bits);
      case "IMUL" -> generateIMul(params, parameter1Bits);
      case "IN" -> generateAssignmentWith2ParametersOnlyOneOperand("Cpu.In", params, parameter1Bits);
      case "INC" -> generateInc(params, parameter1Bits);
      case "INSB", "INSW" -> generateIns(params, parameter1Bits);
      case "INT" -> generateInterrupt(params[0]);
      case "INT3" -> generateInterrupt("3");
      case "IRET" -> "return InterruptRet();";
      case "JA" -> generateConditionalJump("A", params, false);
      case "JBE" -> generateConditionalJump("BE", params, false);
      case "JC" -> generateConditionalJump("C", params, false);
      case "JCXZ" -> generateConditionalJump("CXZ", params, false);
      case "JG" -> generateConditionalJump("G", params, false);
      case "JGE" -> generateConditionalJump("GE", params, false);
      case "JL" -> generateConditionalJump("L", params, false);
      case "JLE" -> generateConditionalJump("LE", params, false);
      case "JMP" -> generateConditionalJump("", params, false);
      case "JMPF" -> generateConditionalJump("", params, true);
      case "JNC" -> generateConditionalJump("NC", params, false);
      case "JNS" -> generateConditionalJump("NS", params, false);
      case "JNO" -> generateConditionalJump("NO", params, false);
      case "JNP" -> generateConditionalJump("NP", params, false);
      case "JNZ" -> generateConditionalJump("NZ", params, false);
      case "JO" -> generateConditionalJump("O", params, false);
      case "JS" -> generateConditionalJump("S", params, false);
      case "JP" -> generateConditionalJump("P", params, false);
      case "JZ" -> generateConditionalJump("Z", params, false);
      case "LAHF" -> "AH = (byte)FlagRegister16;";
      case "LDS" -> generateLXS("DS", params);
      case "LEA" -> generateLea(params);
      case "LES" -> generateLXS("ES", params);
      case "LOCK", "NOP" -> "";
      case "LODSB" -> generateLods(params, 8);
      case "LODSW" -> generateLods(params, 16);
      case "LOOP" -> generateLoop("", params[0]);
      case "LOOPNZ" -> generateLoop("NZ", params[0]);
      case "LOOPZ" -> generateLoop("Z", params[0]);
      case "MOV" -> generateMov(params, parameter1Bits);
      case "MOVSB" -> generateMovs(params, 8);
      case "MOVSW" -> generateMovs(params, 16);
      case "MUL" -> generateMul(params, parameter1Bits);
      case "NEG" -> generateNeg(params, parameter1Bits);
      case "NOT" -> generateNot(params, parameter1Bits);
      case "OR" -> generateAssignmentWith2Parameters("Alu.Or", "|", params);
      case "OUT" -> generateNoAssignmentWith2Parameters("Cpu.Out", params);
      case "OUTSB", "OUTSW" -> generateOuts(params, parameter1Bits);
      case "POP" -> popGenerator.generatePop(params, parameter1Bits);
      case "POPA" -> popGenerator.generatePopAll(parameter1Bits);
      case "POPF" -> popGenerator.generatePopFlags(parameter1Bits);
      case "PUSH" -> pushGenerator.generatePush(params, parameter1Bits);
      case "PUSHA" -> pushGenerator.generatePushAll(parameter1Bits);
      case "PUSHF" -> pushGenerator.generatePushFlags(parameter1Bits);
      case "RCL" -> generateAssignmentWith2Parameters("Alu.Rcl", null, params);
      case "RCR" -> generateAssignmentWith2Parameters("Alu.Rcr", null, params);
      case "RET" -> generateRetNear(params);
      case "RETF" -> generateRetFar(params);
      case "ROL" -> generateAssignmentWith2Parameters("Alu.Rol", null, params);
      case "ROR" -> generateAssignmentWith2Parameters("Alu.Ror", null, params);
      case "SAHF" -> "FlagRegister16 = AH;";
      case "SAR" -> generateAssignmentWith2Parameters("Alu.Sar", null, params);
      case "SBB" -> generateAssignmentWith2Parameters("Alu.Sbb", null, params);
      case "SCASB" -> generateScas(params, 8);
      case "SCASW" -> generateScas(params, 16);
      case "SHL" -> generateAssignmentWith2Parameters("Alu.Shl", "<<", params);
      case "SHR" -> generateAssignmentWith2Parameters("Alu.Shr", ">>", params);
      case "STC" -> "CarryFlag = true;";
      case "STD" -> "DirectionFlag = true;";
      case "STI" -> "InterruptFlag = true;";
      case "STOSB" -> generateStos(params, 8);
      case "STOSW" -> generateStos(params, 16);
      case "SUB" -> generateAssignmentWith2Parameters("Alu.Sub", "-", params);
      case "TEST" -> generateNoAssignmentWith2Parameters("Alu.And", params);
      case "XCHG" -> generateXchg(params, parameter1Bits);
      case "XLAT" -> generateXlat();
      case "XOR" -> generateXor(params);
      default -> null;
    };
  }

  public static String generateFailAsUntested(String message, boolean quotes) {
    String quote = quotes ? "\"" : "";
    return "throw FailAsUntested(" + quote + message + quote + ");";
  }
}
