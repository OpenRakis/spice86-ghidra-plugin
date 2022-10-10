package spice86.generator;

import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class RegisterHandler extends ObjectWithContextAndLog {
  private static final Set<String> REGISTER_NAMES_16_BITS =
      new HashSet<>(Arrays.asList("AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"));
  private static final Set<String> REGISTER_NAMES_8_BITS =
      new HashSet<>(Arrays.asList("AL", "AH", "CL", "CH", "DL", "DH", "BL", "BH"));
  private static final Set<String> REGULAR_REGISTER_NAMES = new HashSet<>();
  private static final Set<String> SEGMENT_REGISTER_NAMES =
      new HashSet<>(Arrays.asList("ES", "CS", "SS", "DS", "FS", "GS"));
  private static final Set<String> ALL_REGISTER_NAMES = new HashSet<>();

  static {
    REGULAR_REGISTER_NAMES.addAll(REGISTER_NAMES_16_BITS);
    REGULAR_REGISTER_NAMES.addAll(REGISTER_NAMES_8_BITS);
    ALL_REGISTER_NAMES.addAll(REGULAR_REGISTER_NAMES);
    ALL_REGISTER_NAMES.addAll(SEGMENT_REGISTER_NAMES);
  }

  private final String csVariable;

  public RegisterHandler(Context context, String csVariable) {
    super(context);
    this.csVariable = csVariable;
  }

  public String substituteRegister(String registerName) {
    if ("CS".equals(registerName)) {
      if (csVariable != null) {
        return csVariable;
      }
      return "/* WARNING, CS value could not be evaluated, CS will not have a correct value */ CS";
    }
    return registerName;
  }

  public String substituteRegistersWithSpice86Expression(String input) {
    String res = input;
    for (String registerName : ALL_REGISTER_NAMES) {
      res = res.replaceAll(registerName, substituteRegister(registerName));
    }
    return res;
  }

  private Set<String> computeSegmentRegistersInInstructionRepresentation(String[] params) {
    Set<String> res = new HashSet<>();
    for (String registerName : SEGMENT_REGISTER_NAMES) {
      for (String param : params) {
        if (param.contains(registerName)) {
          res.add(registerName);
        }
      }
    }
    return res;
  }

  private Set<String> computeSegmentRegistersInInstruction(Object[] inputObjects) {
    Set<String> res = new HashSet<>();
    for (Object inputObject : inputObjects) {
      if (inputObject instanceof ghidra.program.model.lang.Register) {
        String registerName = inputObject.toString();
        if (SEGMENT_REGISTER_NAMES.contains(registerName)) {
          res.add(inputObject.toString());
        }
      }
    }
    return res;
  }

  public Set<String> computeMissingRegisters(String mnemonic, String[] params, Object[] inputObjects) {
    Set<String> registersInRepresentation = computeSegmentRegistersInInstructionRepresentation(params);
    Set<String> registersInInstruction = computeSegmentRegistersInInstruction(inputObjects);
    Set<String> res = new HashSet<>(registersInInstruction);
    res.removeAll(registersInRepresentation);
    boolean usesCs =
        "CALL".equals(mnemonic) || "CALLF".equals(mnemonic) || "RET".equals(mnemonic) || "RETF".equals(mnemonic);
    if (usesCs) {
      // Implicitely touched, but we don't care for address calculation
      res.remove("CS");
    }
    if (usesCs || "PUSH".equals(mnemonic) || "POP".equals(mnemonic) || "PUSHA".equals(mnemonic) || "POPA".equals(
        mnemonic)) {
      // Implicitely touched, but we don't care for address calculation
      res.remove("SS");
      res.remove("SP");
    }
    if (res.size() > 1) {
      log.warning("Found more than one missing segment register in instruction. Segment registers in instruction: "
          + registersInRepresentation + " Segment registers according to ghidra: " + registersInInstruction
          + " delta:"
          + res);
    }
    return res;
  }
}
