package spice86.importer;

import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.Map;

class SegmentedAddressGuesser extends ObjectWithContextAndLog {
  private Map<Integer, Integer> segmentLengths;

  public SegmentedAddressGuesser(Context context, Map<Integer, Integer> segmentLengths) {
    super(context);
    this.segmentLengths = segmentLengths;
  }

  public SegmentedAddress guessSegmentedAddress(int entryPointAddress) {
    int segment = guessSegment(entryPointAddress);
    int offset = entryPointAddress - segment * 0x10;
    return new SegmentedAddress(segment, offset);
  }

  private int guessSegment(int entryPointAddress) {
    int foundSegment = 0;
    for (Map.Entry<Integer, Integer> segmentInformation : segmentLengths.entrySet()) {
      int segment = segmentInformation.getKey();
      int segmentStart = segment * 0x10;
      int segmentEnd = segmentStart + segmentInformation.getValue();
      if (entryPointAddress >= segmentStart && entryPointAddress < segmentEnd) {
        foundSegment = segment;
      }
    }
    log.info("Address " + Utils.toHexWith0X(entryPointAddress) + " corresponds to segment " + Utils.toHexWith0X(
        foundSegment));
    return foundSegment;
  }
}
