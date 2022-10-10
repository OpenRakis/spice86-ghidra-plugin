package spice86.generator.parsing;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import spice86.tools.Context;
import spice86.tools.Log;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.List;

public class ParsedFunctionBuilder extends ObjectWithContextAndLog {
  private ParsedInstructionBuilder parsedInstructionBuilder;

  public ParsedFunctionBuilder(Context context) {
    super(context);
    this.parsedInstructionBuilder = new ParsedInstructionBuilder(context);
  }

  public ParsedFunction createParsedFunction(Function function) {
    String name = function.getName();
    SegmentedAddress entrySegmentedAddress =
        Utils.extractSpice86Address(name);
    long ghidraAddress = function.getEntryPoint().getUnsignedOffset();
    log.info(
        "Parsing function " + name + " at address " + entrySegmentedAddress + " / ghidra address "
            + Utils.toHexWith0X(
            ghidraAddress));
    if (entrySegmentedAddress == null) {
      log.error("Could not determine segmented address for function entry point, aborting.");
      return null;
    }
    if (ghidraAddress != entrySegmentedAddress.toPhysical()) {
      log.error(
          "Function entry point in ghidra is not the same as the one in spice86, this could be because ghidra created a function with the same name.");
      return null;
    }

    List<ParsedInstruction> instructionsBeforeEntry = new ArrayList<>();
    List<ParsedInstruction> instructionsAfterEntry = new ArrayList<>();
    boolean success =
        dispatchInstructions(function, entrySegmentedAddress, instructionsBeforeEntry, instructionsAfterEntry);
    if (!success) {
      log.error("Couldn't read the instructions for function " + name + ". Not generating code for it.");
      return null;
    }
    return new ParsedFunction(function, name, entrySegmentedAddress, instructionsBeforeEntry, instructionsAfterEntry);
  }

  private SegmentedAddress getInstructionAddress(Log log, Instruction instruction,
      SegmentedAddress entrySegmentedAddress) {
    long instructionAddress = instruction.getAddress().getUnsignedOffset();
    long entryAddress = entrySegmentedAddress.toPhysical();
    long delta = instructionAddress - entryAddress;
    long offset = entrySegmentedAddress.getOffset() + delta;
    if (offset < 0 || offset > 0xFFFF) {
      log.error("Instruction outside of function segment. Function entry: " + entrySegmentedAddress
          + " / Instruction address: " + Utils.toHexWithout0X(instructionAddress)
          + " / Instruction delta: " + delta
          + " / Instruction offset: " + offset);
      return null;
    }
    return new SegmentedAddress(entrySegmentedAddress.getSegment(), (int)offset);
  }

  /**
   * Dispatches the instruction of the given function to 2 lists, one for the instructions before the entry point and one for those after
   */
  private boolean dispatchInstructions(Function function, SegmentedAddress entrySegmentedAddress,
      List<ParsedInstruction> instructionsBeforeEntry, List<ParsedInstruction> instructionsAfterEntry) {
    AddressSetView body = function.getBody();
    String name = function.getName();
    log.info("Body ranges for " + name + ":" + body);
    // Functions can be split accross the exe, they are divided in ranges and typically the code will jump accross ranges.
    // Let's get a list of all the instructions of the function split between instructions that are before the entry and after the entry.
    for (AddressRange addressRange : body) {
      Address min = addressRange.getMinAddress();
      Address max = addressRange.getMaxAddress();
      int maxAddress = (int)max.getUnsignedOffset();
      log.info("Range: " + min + " -> " + max);
      Instruction instruction = context.getProgram().getListing().getInstructionAt(min);
      if (instruction == null) {
        log.error(" Instruction at " + min + " is null");
        return false;
      }
      Instruction before;
      int nextAddress;
      do {
        SegmentedAddress
            instructionAddress = getInstructionAddress(log, instruction, entrySegmentedAddress);
        if (instructionAddress == null) {
          return false;
        }
        ParsedInstruction parsedInstruction =
            parsedInstructionBuilder.parseInstruction(instruction, instructionAddress);
        dispatchInstruction(parsedInstruction, entrySegmentedAddress, instructionsBeforeEntry,
            instructionsAfterEntry);
        log.info("Attached instruction to function " + name + ": " + parsedInstruction);
        nextAddress =
            parsedInstruction.getNextInstructionSegmentedAddress().toPhysical();
        log.info("Next address is " + Utils.toHexWith0X(nextAddress));
        if (nextAddress > maxAddress) {
          break;
        }
        before = instruction;
        instruction = instruction.getNext();
        if (instruction == null) {
          log.error(" Instruction after " + before.getAddress() + " is null");
          return false;
        }
      } while (true);
    }
    return true;
  }

  private void dispatchInstruction(ParsedInstruction instruction, SegmentedAddress entry,
      List<ParsedInstruction> instructionsBeforeEntry, List<ParsedInstruction> instructionsAfterEntry) {
    if (instruction == null) {
      return;
    }
    SegmentedAddress instructionAddress = instruction.getInstructionSegmentedAddress();
    if (instructionAddress.compareTo(entry) < 0) {
      instructionsBeforeEntry.add(instruction);
    } else {
      instructionsAfterEntry.add(instruction);
    }
  }
}
