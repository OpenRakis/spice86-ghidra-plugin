package spice86.importer;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import org.apache.commons.collections4.IteratorUtils;
import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.List;

class FunctionSplitter extends ObjectWithContextAndLog {
  private Program program;
  private SegmentedAddressGuesser segmentedAddressGuesser;
  private FunctionCreator functionCreator;

  public FunctionSplitter(Context context, SegmentedAddressGuesser segmentedAddressGuesser,
      FunctionCreator functionCreator) {
    super(context);
    this.program = context.getProgram();
    this.segmentedAddressGuesser = segmentedAddressGuesser;
    this.functionCreator = functionCreator;
  }

  public int splitAllFunctions() throws InvalidInputException, OverlappingFunctionException {
    List<Function> functions = Utils.getAllFunctions(program);
    int numberOfCreated = 0;

    for (Function function : functions) {
      numberOfCreated += splitOneFunction(function);
    }
    log.info("Splitted " + numberOfCreated + " functions.");
    return numberOfCreated;
  }

  private int splitOneFunction(Function function)
      throws InvalidInputException, OverlappingFunctionException {
    int numberOfCreated = 0;
    AddressSetView body = function.getBody();
    List<AddressRange> addressRangeList = IteratorUtils.toList(body.iterator());
    if (addressRangeList.size() <= 1) {
      log.info("Function " + function.getName() + " Doesn't need to be split");
      // Nothing to split
      return 0;
    }
    log.info("Function " + function.getName() + " Needs to be split in " + addressRangeList.size());
    Listing listing = program.getListing();
    Address entryPoint = function.getEntryPoint();
    // Removing the function since it is going to be recreated in chunks
    functionCreator.removeFunctionAt(entryPoint);

    AddressRange entryPointRange = findRangeWithEntryPoint(addressRangeList, entryPoint);
    for (AddressRange addressRange : addressRangeList) {
      AddressSetView newBody = new AddressSet(addressRange);
      if (addressRange == entryPointRange) {
        String name = function.getName();
        log.info("Re-creating function named " + name + " with body " + newBody + " and entry point " + entryPoint);
        functionCreator.createFunctionWithDefinedBody(name, entryPoint, addressRange);
      } else {
        Address start = addressRange.getMinAddress();
        String newName = generateSplitName(start);
        log.info("Creating additional function from split named " + newName + " with body " + newBody);
        functionCreator.createFunctionWithDefinedBody(newName, start, addressRange);
        numberOfCreated++;
      }
    }
    return numberOfCreated;
  }

  private AddressRange findRangeWithEntryPoint(List<AddressRange> addressRangeList, Address entryPoint) {
    for (AddressRange addressRange : addressRangeList) {
      if (addressRange.contains(entryPoint)) {
        return addressRange;
      }
    }
    return null;
  }

  private String generateSplitName(Address start) {
    SegmentedAddress segmentedAddress = segmentedAddressGuesser.guessSegmentedAddress((int)start.getUnsignedOffset());
    // Do not include original name in the new name as it is often unrelated
    return "split_" + Utils.toHexSegmentOffsetPhysical(segmentedAddress);
  }
}
