package spice86.tools.config.reader;

import spice86.tools.Context;
import spice86.tools.ObjectWithContextAndLog;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class SymbolsFileReader extends ObjectWithContextAndLog {
  public SymbolsFileReader(Context context) {
    super(context);
  }

  public Map<SegmentedAddress, String> readFunctionFile(String filePath) throws IOException {
    log.info("Reading symbols file");
    Map<SegmentedAddress, String> res = new HashMap<>();
    List<String> lines = Files.readAllLines(Paths.get(filePath));
    for (String line : lines) {
      parseLine(res, line);
    }
    return res;
  }

  private void parseLine(Map<SegmentedAddress, String> res, String line) {
    String[] split = line.split(" ");
    if (split.length != 3) {
      // Not a function line
      return;
    }
    String type = split[2];
    if (!"f".equals(type)) {
      // Not a function line
      return;
    }
    String name = split[0];
    String[] nameSplit = name.split("_");
    if (nameSplit.length < 4) {
      // Format is not correct, we can't use this line
      return;
    }
    try {
      int segment = Utils.parseHex16(nameSplit[nameSplit.length - 3]);
      int offset = Utils.parseHex16(nameSplit[nameSplit.length - 2]);
      SegmentedAddress address = new SegmentedAddress(segment, offset);
      res.put(address, name);
    } catch (NumberFormatException nfe) {
      return;
    }
  }
}
