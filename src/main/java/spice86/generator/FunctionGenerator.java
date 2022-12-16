package spice86.generator;

import org.apache.commons.collections4.CollectionUtils;
import spice86.generator.instructiongenerator.InstructionGenerator;
import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedInstruction;
import spice86.generator.parsing.ParsedProgram;
import spice86.tools.Context;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FunctionGenerator {
  private final Context context;
  private final Log log;
  private final ParsedProgram parsedProgram;
  private final ParsedFunction parsedFunction;

  public FunctionGenerator(Context context, ParsedProgram parsedProgram,
      ParsedFunction parsedFunction) {
    this.context = context;
    this.log = context.getLog();
    this.parsedProgram = parsedProgram;
    this.parsedFunction = parsedFunction;
  }

  public String outputCSharp() {
    StringBuilder res = new StringBuilder();
    String name = parsedFunction.getName();
    log.info("Generating C# code for function " + name);
    res.append("public virtual Action " + name + "(int loadOffset) {\n");
    List<ParsedInstruction> instructionsBeforeEntry = parsedFunction.getInstructionsBeforeEntry();
    List<ParsedInstruction> instructionsAfterEntry = parsedFunction.getInstructionsAfterEntry();
    Set<String> generatedTempVars = new HashSet<>();
    SegmentedAddress firstInstructionOfBeforeSectionAddress = null;
    if (!instructionsBeforeEntry.isEmpty()) {
      firstInstructionOfBeforeSectionAddress = instructionsBeforeEntry.get(0).getInstructionSegmentedAddress();
    }
    String gotosFromOutsideHandlingSection =
        generateGotoFromOutsideAndInstructionSkip(firstInstructionOfBeforeSectionAddress,
            parsedFunction.getEntrySegmentedAddress());
    if (!gotosFromOutsideHandlingSection.isEmpty()) {
      res.append(Utils.indent(gotosFromOutsideHandlingSection, 2) + "\n");
    }
    if (!instructionsBeforeEntry.isEmpty()) {
      writeInstructions(res, instructionsBeforeEntry, 2, generatedTempVars, false);
      res.append("  entry:\n");
    }
    writeInstructions(res, instructionsAfterEntry, 2, generatedTempVars, true);
    res.append("}\n");
    return res.toString();
  }

  private boolean areAllExternalJumpsToEntry(SegmentedAddress entryAddress,
      Collection<SegmentedAddress> jumpTargets) {
    if (jumpTargets.isEmpty()) {
      return true;
    }
    for (SegmentedAddress target : jumpTargets) {
      if (!target.equals(entryAddress)) {
        return false;
      }
    }
    return true;
  }

  private String generateGotoFromOutsideAndInstructionSkip(SegmentedAddress firstInstructionOfBeforeSectionAddress,
      SegmentedAddress entryAddress) {
    Collection<SegmentedAddress> jumpTargets = CollectionUtils.emptyIfNull(
        parsedProgram.getJumpsFromOutsideForFunction(parsedFunction.getEntrySegmentedAddress()));

    StringBuilder res = new StringBuilder("entrydispatcher:\n");
    if (firstInstructionOfBeforeSectionAddress == null && areAllExternalJumpsToEntry(entryAddress, jumpTargets)) {
      return res + "if(loadOffset != 0) {\n  " + InstructionGenerator.generateFailAsUntested(
          "External goto not supported for this function.", true) + "\n}";
    }
    res.append("switch(loadOffset) {\n");
    for (SegmentedAddress target : jumpTargets) {
      if (target.equals(firstInstructionOfBeforeSectionAddress) || target.equals(entryAddress)) {
        // firstInstructionOfBeforeSectionAddress case is handled separately, do not do double case
        // entry is not needed as callers will call function with 0 in parameter
        continue;
      }
      String caseString = "  case " + Utils.toHexWith0X(target.toPhysical() - parsedProgram.getCs1Physical()) + ":";
      String gotoTarget = JumpCallTranslator.getLabelToAddress(target, false);
      String jumpSourceAddresses = getJumpSourceAddressesToString(target);
      res.append(
          caseString + " goto " + gotoTarget + ";break; // Target of external jump from " + jumpSourceAddresses
              + "\n");
    }
    if (firstInstructionOfBeforeSectionAddress != null) {
      // instructions before entry point are just after this switch
      res.append("  case " + Utils.toHexWith0X(
          firstInstructionOfBeforeSectionAddress.toPhysical() - parsedProgram.getCs1Physical())
          + ": break; // Instructions before entry targeted by " + getJumpSourceAddressesToString(
          firstInstructionOfBeforeSectionAddress) + "\n");
      // default address 0 is for entry point, goto there as there are instructions between
      res.append(
          "  case 0: goto entry; break; // 0 is the entry point ghidra detected, but in this case function start is not entry point\n");
    } else {
      // default address 0 is for entry point, instructions are just after the switch
      res.append("  case 0: break; // 0 is the entry point ghidra detected, just after this switch\n");
    }
    if (!jumpTargets.isEmpty()) {
      // Only makes sense to generate this when there are labels accessible from outside
      res.append("  default: " + InstructionGenerator.generateFailAsUntested(
          "\"Could not find any label from outside with address \" + loadOffset", false) + "\n");
    }
    res.append("}");
    return res.toString();
  }

  private String getJumpSourceAddressesToString(SegmentedAddress target) {
    return CollectionUtils.emptyIfNull(parsedProgram.getJumpTargetOrigins(target))
        .stream()
        .map(Utils::toHexWith0X)
        .collect(Collectors.joining(", "));
  }

  private void writeInstructions(StringBuilder stringBuilder, List<ParsedInstruction> instructions, int indent,
      Set<String> generatedTempVars, boolean returnExpected) {
    Iterator<ParsedInstruction> instructionIterator = instructions.iterator();
    while (instructionIterator.hasNext()) {
      ParsedInstruction parsedInstruction = instructionIterator.next();
      InstructionGenerator instructionGenerator =
          new InstructionGenerator(context, parsedProgram, parsedFunction, parsedInstruction,
              generatedTempVars);
      stringBuilder.append(Utils.indent(instructionGenerator.convertInstructionToSpice86(true), indent) + "\n");
      boolean isLast = !instructionIterator.hasNext();
      if (isLast && returnExpected && !instructionGenerator.isFunctionReturn() && !instructionGenerator.isGoto()) {
        // Last instruction should have been a return, but it is not.
        // It means the ASM code will continue to the next function. Generate a function call if possible.
        SegmentedAddress next = parsedInstruction.getNextInstructionSegmentedAddress();
        stringBuilder.append(
            Utils.indent(generateMissingReturn(next, instructionGenerator.getJumpCallTranslator()), indent) + "\n");
      }
    }
  }

  private String generateMissingReturn(SegmentedAddress nextInstructionAddress,
      JumpCallTranslator jumpCallTranslator) {
    ParsedInstruction nextParsedInstruction = parsedProgram.getInstructionAtSegmentedAddress(nextInstructionAddress);
    log.info("Generating missing return.");
    if (nextParsedInstruction == null) {
      return InstructionGenerator.generateFailAsUntested(
          "Function does not end with return and no instruction after the body ...", true);
    }
    log.info("Next instruction is " + nextParsedInstruction);
    ParsedFunction function = parsedProgram.getFunctionAtSegmentedAddressEntryPoint(nextInstructionAddress);
    if (function != null) {
      return "// Function call generated as ASM continues to next function entry point without return\n"
          + jumpCallTranslator.functionToDirectCSharpCallWithReturn(function, null);
    } else {
      function = parsedProgram.getFunctionAtSegmentedAddressAny(nextInstructionAddress);
      if (function != null) {
        return "// Function call generated as ASM continues to next function body without return\n"
            + jumpCallTranslator.functionToDirectCSharpCallWithReturn(function, nextInstructionAddress.toPhysical());
      }
    }
    return InstructionGenerator.generateFailAsUntested(
        "Function does not end with return and no other function found after the body at address "
            + Utils.toHexSegmentOffsetPhysical(nextInstructionAddress), true);
  }
}
