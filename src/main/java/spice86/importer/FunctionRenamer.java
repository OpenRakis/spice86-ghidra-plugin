package spice86.importer;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

class FunctionRenamer extends ObjectWithContextAndLog {
  private Program program;
  private SegmentedAddressGuesser segmentedAddressGuesser;

  public FunctionRenamer(Context context, SegmentedAddressGuesser segmentedAddressGuesser) {
    super(context);
    this.program = context.getProgram();
    this.segmentedAddressGuesser = segmentedAddressGuesser;
  }

  protected int renameAll() throws Exception {
    FunctionIterator functionIterator = Utils.getFunctionIterator(program);
    int renamed = 0;
    while (functionIterator.hasNext()) {
      if (renameFunction(functionIterator.next())) {
        renamed++;
      }
    }
    log.info("Renamed " + renamed + " functions");
    return renamed;
  }

  private boolean renameFunction(Function function) throws InvalidInputException, DuplicateNameException {
    String functionName = function.getName();
    if (function.isThunk()) {
      log.info("Changing Thunk function to normal function for " + functionName);
      function.setThunkedFunction(null);
    }
    SegmentedAddress nameAddress = Utils.extractSpice86Address(functionName);
    long ghidraAddress = function.getEntryPoint().getUnsignedOffset();
    if (nameAddress != null) {
      if (nameAddress.toPhysical() == ghidraAddress) {
        // Nothing to do
        return false;
      }
      // Can happen when ghidra creates a thunk function and chooses to use the name of the jump target for function name.
      log.warning("Function at address " + Utils.toHexWith0X(ghidraAddress) + " is named " + functionName
          + ". Address in name and ghidra address do not match. Renaming it.");
    }
    String prefix = "ghidra_guess_";
    log.info("processing " + functionName + " at address " + Utils.toHexWith0X((int)ghidraAddress));
    SegmentedAddress address = guessAddress(function);
    String name = prefix + Utils.toHexSegmentOffsetPhysical(address);
    function.setName(name, SourceType.USER_DEFINED);
    return true;
  }

  private SegmentedAddress guessAddress(Function function) {
    int entryPointAddress = (int)function.getEntryPoint().getUnsignedOffset();
    return segmentedAddressGuesser.guessSegmentedAddress(entryPointAddress);
  }
}
