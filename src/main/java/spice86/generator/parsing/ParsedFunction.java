package spice86.generator.parsing;

import com.google.gson.Gson;
import ghidra.program.model.listing.Function;
import spice86.tools.SegmentedAddress;

import java.util.List;

public class ParsedFunction {
  private final transient Function function;
  private final String name;
  private final SegmentedAddress entrySegmentedAddress;
  private final List<ParsedInstruction> instructionsBeforeEntry;
  private final List<ParsedInstruction> instructionsAfterEntry;

  public ParsedFunction(Function function, String name, SegmentedAddress entrySegmentedAddress,
      List<ParsedInstruction> instructionsBeforeEntry, List<ParsedInstruction> instructionsAfterEntry) {
    this.function = function;
    this.name = name;
    this.entrySegmentedAddress = entrySegmentedAddress;
    this.instructionsBeforeEntry = instructionsBeforeEntry;
    this.instructionsAfterEntry = instructionsAfterEntry;
  }

  public String getName() {
    return name;
  }

  public SegmentedAddress getEntrySegmentedAddress() {
    return entrySegmentedAddress;
  }

  public List<ParsedInstruction> getInstructionsBeforeEntry() {
    return instructionsBeforeEntry;
  }

  public List<ParsedInstruction> getInstructionsAfterEntry() {
    return instructionsAfterEntry;
  }

  @Override public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    return (obj instanceof ParsedFunction other) && other.entrySegmentedAddress.equals(this.entrySegmentedAddress);
  }

  @Override public int hashCode() {
    return entrySegmentedAddress.hashCode();
  }

  @Override public String toString() {
    return new Gson().toJson(this);
  }
}
