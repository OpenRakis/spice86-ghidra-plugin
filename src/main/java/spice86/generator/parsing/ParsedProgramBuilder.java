package spice86.generator.parsing;

import spice86.generator.CodeToInject;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;
import spice86.tools.config.ByteModificationRecord;
import spice86.tools.config.CodeGeneratorConfig;
import spice86.tools.config.ExecutionFlow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ParsedProgramBuilder extends ObjectWithContextAndLog {
  public ParsedProgramBuilder(Context context) {
    super(context);
  }

  public ParsedProgram createParsedProgram(List<ParsedFunction> functions, ExecutionFlow executionFlow,
      CodeGeneratorConfig codeGeneratorConfig) {
    ParsedProgram res = new ParsedProgram();
    res.executionFlow = executionFlow;
    res.entryPoints.putAll(
        functions.stream().collect(Collectors.toMap(f -> f.getEntrySegmentedAddress().toPhysical(), f -> f)));
    mapInstructions(functions, res);

    generateSegmentVariables(functions, res);
    res.generateCheckExternalEventsBeforeInstruction =
        codeGeneratorConfig.isGenerateCheckExternalEventsBeforeInstruction();
    res.codeToInject = getCodeToInject(res.codeSegmentVariables, codeGeneratorConfig.getCodeToInject());
    res.instructionsToReplace =
        resolveInstructionsToReplace(res.codeSegmentVariables, codeGeneratorConfig.getInstructionsToReplace());
    // Map address of function -> Set of externally reachable labels
    registerOutOfFunctionJumps(executionFlow, res);
    generateJumpsToFrom(executionFlow, res);
    registerPossibleInstructionsBytes(executionFlow, res);
    registerModifiedInstructions(executionFlow, res);
    return res;
  }

  private void mapInstructions(List<ParsedFunction> functions, ParsedProgram res) {
    log.info("Mapping instructions");
    for (ParsedFunction parsedFunction : functions) {
      // Map address of instruction -> function
      res.instructionAddressToFunction.putAll(
          mapFunctionByInstructionAddress(parsedFunction, parsedFunction.getInstructionsBeforeEntry()));
      res.instructionAddressToFunction.putAll(
          mapFunctionByInstructionAddress(parsedFunction, parsedFunction.getInstructionsAfterEntry()));
      // Map address of instruction -> instruction
      res.instructionAddressToInstruction.putAll(
          mapInstructionByInstructionAddress(parsedFunction.getInstructionsBeforeEntry()));
      res.instructionAddressToInstruction.putAll(
          mapInstructionByInstructionAddress(parsedFunction.getInstructionsAfterEntry()));
    }
  }

  private void generateSegmentVariables(List<ParsedFunction> functions, ParsedProgram res) {
    log.info("Generating segment variables");
    List<Integer> segments = functions.stream()
        .map(ParsedFunction::getEntrySegmentedAddress)
        .map(SegmentedAddress::getSegment)
        .distinct()
        .sorted()
        .toList();
    int csIndex = 1;
    for (Integer segment : segments) {
      String varName = "cs" + csIndex++;
      res.codeSegmentVariables.put(segment, varName);
      log.info("Variable " + varName + " created with value " + Utils.toHexWithout0X(segment));
    }
    if (!res.codeSegmentVariables.isEmpty()) {
      res.cs1 = res.codeSegmentVariables.keySet().iterator().next() * 0x10;
    }
    log.info(
        "First segment address is " + Utils.toHexWithout0X(res.cs1) + " variable " + res.codeSegmentVariables.get(
            res.cs1 / 0x10));
  }

  private CodeToInject getCodeToInject(Map<Integer, String> codeSegmentVariables,
      Map<String, List<String>> codeToInject) {
    Map<SegmentedAddress, List<String>> codeToInjectReversed = new HashMap<>();
    if (codeToInject != null) {
      for (Map.Entry<String, List<String>> entry : codeToInject.entrySet()) {
        String code = entry.getKey();
        List<String> addressExpressions = entry.getValue();
        for (String addressExpression : addressExpressions) {
          SegmentedAddress segmentedAddress = toSegmentedAddress(codeSegmentVariables, addressExpression);
          List<String> codeList = codeToInjectReversed.computeIfAbsent(segmentedAddress, a -> new ArrayList());
          codeList.add(code);
        }
      }
    }
    return new CodeToInject(codeToInjectReversed);
  }

  private Map<SegmentedAddress, String> resolveInstructionsToReplace(Map<Integer, String> codeSegmentVariables,
      Map<String, String> instructionsToReplace) {
    Map<SegmentedAddress, String> res = new HashMap<>();
    if (instructionsToReplace != null) {
      for (Map.Entry<String, String> entry : instructionsToReplace.entrySet()) {
        SegmentedAddress segmentedAddress = toSegmentedAddress(codeSegmentVariables, entry.getKey());
        String code = entry.getValue();
        res.put(segmentedAddress, code);
      }
    }
    return res;
  }

  private SegmentedAddress toSegmentedAddress(Map<Integer, String> codeSegmentVariables,
      String addressExpression) {
    String[] split = addressExpression.split(":");
    Integer segment = getSegmentValue(codeSegmentVariables, split[0]);
    Integer offset = Utils.parseHex16(split[1]);
    return new SegmentedAddress(segment, offset);
  }

  private Integer getSegmentValue(Map<Integer, String> codeSegmentVariables, String segmentName) {
    return codeSegmentVariables.entrySet()
        .stream()
        .filter(e -> e.getValue().equalsIgnoreCase(segmentName))
        .map(Map.Entry::getKey)
        .findAny()
        .orElse(null);
  }

  private void generateJumpsToFrom(ExecutionFlow executionFlow, ParsedProgram res) {
    for (Map.Entry<Integer, List<SegmentedAddress>> jumpFromTo : executionFlow.getJumpsFromTo().entrySet()) {
      Integer fromAddress = jumpFromTo.getKey();
      for (SegmentedAddress toAddress : jumpFromTo.getValue()) {
        Set<Integer> fromAddresses = res.jumpsToFrom.computeIfAbsent(toAddress, a -> new HashSet<>());
        fromAddresses.add(fromAddress);
      }
    }
  }

  private void registerOutOfFunctionJumps(ExecutionFlow executionFlow, ParsedProgram res) {
    log.info("Registering out of function jumps");
    for (Map.Entry<Integer, List<SegmentedAddress>> jumpFromTo : executionFlow.getJumpsFromTo().entrySet()) {
      Integer fromAddress = jumpFromTo.getKey();
      ParsedFunction fromFunction = res.getFunctionAtAddressAny(fromAddress);
      if (fromFunction == null) {
        log.error("No source function found at address " + Utils.toHexWithout0X(fromAddress) + " for jump.");
        continue;
      }
      for (SegmentedAddress toAddress : jumpFromTo.getValue()) {
        ParsedFunction toFunction = res.getFunctionAtSegmentedAddressAny(toAddress);
        if (toFunction == null) {
          log.error("No target function found at address " + Utils.toHexSegmentOffsetPhysical(toAddress));
          continue;
        }
        if (toFunction.equals(fromFunction)) {
          // filter out self
          continue;
        }
        // At this point toAddress belongs to toFunction which is different from fromFunction
        log.info("Found an externally accessible label at address " + Utils.toHexSegmentOffsetPhysical(toAddress)
            + ". This address belongs to function " + toFunction.getName());
        // Let's register it as externally targeted label
        Set<SegmentedAddress> jumpsFromOutsideForFunction =
            res.jumpsFromOutsidePerFunction.computeIfAbsent(toFunction.getEntrySegmentedAddress(),
                a -> new HashSet<>());
        jumpsFromOutsideForFunction.add(toAddress);
      }
    }
  }

  private void registerPossibleInstructionsBytes(ExecutionFlow executionFlow, ParsedProgram res) {
    res.possibleInstructionByteValues = executionFlow.getExecutableAddressWrittenBy()
        .entrySet()
        .stream()
        .collect(Collectors.toMap(e -> e.getKey(), e -> getPossibleInstructionByteValues(e.getValue())));
  }

  private void registerModifiedInstructions(ExecutionFlow executionFlow, ParsedProgram res) {
    log.info("Registering modified code to parsed instructions");
    ParsedInstructionBuilder parsedInstructionBuilder = new ParsedInstructionBuilder(context);
    for (ParsedInstruction parsedInstruction : res.instructionAddressToInstruction.values()) {
      log.info("Processing modified code for " + parsedInstruction.toString());
      parsedInstructionBuilder.completeWithSelfModifyingCodeInformation(parsedInstruction,
          res.possibleInstructionByteValues);
    }
  }

  private Set<Integer> getPossibleInstructionByteValues(
      Map<Integer, Set<ByteModificationRecord>> byteValuesAtAddress) {
    return byteValuesAtAddress.values()
        .stream()
        .flatMap(Collection::stream)
        .map(byteModificationRecord -> Arrays.asList(byteModificationRecord.getOldValue(),
            byteModificationRecord.getNewValue()))
        .flatMap(Collection::stream)
        .collect(Collectors.toSet());
  }

  private Map<Integer, ParsedInstruction> mapInstructionByInstructionAddress(List<ParsedInstruction> list) {
    return list.stream().collect(Collectors.toMap(i -> i.getInstructionSegmentedAddress().toPhysical(), i -> i));
  }

  private Map<Integer, ParsedFunction> mapFunctionByInstructionAddress(ParsedFunction parsedFunction,
      List<ParsedInstruction> list) {
    return list.stream()
        .collect(Collectors.toMap(i -> i.getInstructionSegmentedAddress().toPhysical(), i -> parsedFunction));
  }

}
