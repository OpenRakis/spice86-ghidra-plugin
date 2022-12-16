package spice86.generator.instructiongenerator;

import spice86.generator.ParameterTranslator;
import spice86.generator.parsing.ParsedInstruction;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class PushGenerator {
  private final ParameterTranslator parameterTranslator;
  private final ParsedInstruction parsedInstruction;

  public PushGenerator(ParameterTranslator parameterTranslator, ParsedInstruction parsedInstruction) {
    this.parameterTranslator = parameterTranslator;
    this.parsedInstruction = parsedInstruction;
  }

  public String generatePushAll(Integer bits) {
    String spTempVar = parameterTranslator.generateTempVar("sp");
    String spVar = bits == 16 ? "SP" : "ESP";
    List<String> registers = bits == 16 ?
        Arrays.asList("AX", "CX", "DX", "BX", spTempVar, "BP", "SI", "DI") :
        Arrays.asList("EAX", "ECX", "EDX", "EBX", spTempVar, "EBP", "ESI", "EDI");
    String pushCode =
        registers.stream()
            .map(value -> generatePushToExpression(value, bits)).collect(Collectors.joining("\n"));
    String tempVarAssignment = parameterTranslator.generateAssignmentWithType(parameterTranslator.toUnsignedType(bits), spTempVar, spVar);
    return tempVarAssignment + '\n' + pushCode;
  }

  public String generatePush(String[] ghidraParams, Integer bits) {
    String expression = parameterTranslator.toSpice86Value(ghidraParams[0], bits);
    if (parsedInstruction.getParameter1BitLength() == 8) {
      expression = parameterTranslator.signExtendByteToUInt(expression, parsedInstruction.getInstructionBitLength());
    }
    return generatePushToExpression(expression, bits);
  }

  public String generatePushFlags(Integer bits) {
    return generatePushToExpression("FlagRegister" + bits, bits);
  }

  private String generatePushToExpression(String value, Integer bits) {
    return "Stack.Push" + bits + "(" + value + ");";
  }
}
