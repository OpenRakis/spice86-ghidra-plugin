package spice86.generator.parsing;

import ghidra.program.model.address.Address;
import spice86.generator.CodeToInject;
import spice86.tools.SegmentedAddress;
import spice86.tools.config.ByteModificationRecord;
import spice86.tools.config.ExecutionFlow;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class ParsedProgram {
  protected ExecutionFlow executionFlow;
  // List of addresses where to inject code to check timer and other external interrupts
  protected CodeToInject codeToInject;
  protected boolean generateCheckExternalEventsBeforeInstruction;
  protected Map<SegmentedAddress, String> instructionsToReplace;
  protected Map<Integer, ParsedFunction> instructionAddressToFunction = new HashMap<>();
  protected Map<Integer, ParsedInstruction> instructionAddressToInstruction = new HashMap<>();
  protected Map<SegmentedAddress, Set<SegmentedAddress>> jumpsFromOutsidePerFunction = new HashMap<>();
  // Sorted by entry address
  protected Map<Integer, ParsedFunction> entryPoints = new TreeMap<>();
  protected Map<Integer, String> codeSegmentVariables = new TreeMap<>();
  protected Map<SegmentedAddress, Set<Integer>> jumpsToFrom = new TreeMap<>();
  // Address -> list of values this address can be at
  protected Map<Integer, Set<Integer>> possibleInstructionByteValues = new TreeMap<>();
  protected int cs1;

  public ExecutionFlow getExecutionFlow() {
    return executionFlow;
  }

  public boolean isGenerateCheckExternalEventsBeforeInstruction() {
    return generateCheckExternalEventsBeforeInstruction;
  }

  public CodeToInject getCodeToInject() {
    return codeToInject;
  }

  public String getInstructionReplacement(SegmentedAddress address) {
    return instructionsToReplace.get(address);
  }

  public Set<SegmentedAddress> getJumpsFromOutsideForFunction(SegmentedAddress address) {
    return jumpsFromOutsidePerFunction.get(address);
  }

  public Map<Integer, ParsedFunction> getEntryPoints() {
    return entryPoints;
  }

  public Set<Integer> getInstructionAddresses() {
    return instructionAddressToInstruction.keySet();
  }

  public ParsedInstruction getInstructionAtAddress(int address) {
    return instructionAddressToInstruction.get(address);
  }

  public ParsedInstruction getInstructionAtSegmentedAddress(SegmentedAddress address) {
    return getInstructionAtAddress(address.toPhysical());
  }

  public ParsedInstruction getInstructionAfter(ParsedInstruction instruction) {
    SegmentedAddress currentAddress = instruction.getInstructionSegmentedAddress();
    SegmentedAddress nextAddress = new SegmentedAddress(currentAddress.getSegment(),
        currentAddress.getOffset() + instruction.getInstructionLength());
    return getInstructionAtSegmentedAddress(nextAddress);
  }

  public ParsedFunction getFunctionAtSegmentedAddressAny(SegmentedAddress address) {
    return getFunctionAtAddressAny(address.toPhysical());
  }

  public ParsedFunction getFunctionAtGhidraAddressAny(Address address) {
    return getFunctionAtAddressAny((int)address.getUnsignedOffset());
  }

  public ParsedFunction getFunctionAtAddressAny(int address) {
    return instructionAddressToFunction.get(address);
  }

  public ParsedFunction getFunctionAtSegmentedAddressEntryPoint(SegmentedAddress address) {
    return getFunctionAtAddressEntryPoint(address.toPhysical());
  }

  public ParsedFunction getFunctionAtGhidraAddressEntryPoint(Address address) {
    return getFunctionAtAddressEntryPoint((int)address.getUnsignedOffset());
  }

  private ParsedFunction getFunctionAtAddressEntryPoint(int address) {
    return entryPoints.get(address);
  }

  public Map<Integer, String> getCodeSegmentVariables() {
    return codeSegmentVariables;
  }

  public int getCs1Physical() {
    return cs1;
  }

  public Set<Integer> getPossibleInstructionByteValues(int address) {
    return possibleInstructionByteValues.get(address);
  }

  public Set<Integer> getAddressesModifyingExecutableAddress(int address) {
    Map<Integer, Set<ByteModificationRecord>> modifiedByInstructions =
        this.executionFlow.getExecutableAddressWrittenBy().get(address);
    if (modifiedByInstructions == null) {
      return Collections.emptySet();
    }
    return modifiedByInstructions.keySet();
  }

  public Set<Integer> getJumpTargetOrigins(SegmentedAddress address) {
    return jumpsToFrom.get(address);
  }
}
