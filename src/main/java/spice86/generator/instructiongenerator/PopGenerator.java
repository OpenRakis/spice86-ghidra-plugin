package spice86.generator.instructiongenerator;

import spice86.generator.ParameterTranslator;

public class PopGenerator {
  private final ParameterTranslator parameterTranslator;

  public PopGenerator(ParameterTranslator parameterTranslator) {
    this.parameterTranslator = parameterTranslator;
  }

  public String generatePopAll(Integer bits) {
    String prefix = bits == 16 ? "" : "E";
    return generatePopToGhidraExpression(prefix + "DI", bits) + '\n'
        + generatePopToGhidraExpression(prefix + "SI", bits) + '\n'
        + generatePopToGhidraExpression(prefix + "BP", bits) + '\n'
        + "// not restoring SP, popping empty"
        + generatePopToExpression(null, bits) + '\n'
        + generatePopToGhidraExpression(prefix + "BX", bits) + '\n'
        + generatePopToGhidraExpression(prefix + "DX", bits) + '\n'
        + generatePopToGhidraExpression(prefix + "CX", bits) + '\n'
        + generatePopToGhidraExpression(prefix + "AX", bits);
  }

  public String generatePop(String[] ghidraParams, Integer bits) {
    return generatePopToExpression(parameterTranslator.toSpice86Value(ghidraParams[0], bits), bits);
  }

  public String generatePopFlags(Integer bits) {
    return generatePopToExpression("FlagRegister" + bits, bits);
  }

  private String generatePopToGhidraExpression(String register, Integer bits) {
    return generatePopToExpression(parameterTranslator.toSpice86Value(register, bits), bits);
  }

  private String generatePopToExpression(String expression, Integer bits) {
    String operation = "Stack.Pop" + bits + "();";
    if (expression != null) {
      return parameterTranslator.generateAssignment(expression, operation);
    }
    return operation;
  }
}
