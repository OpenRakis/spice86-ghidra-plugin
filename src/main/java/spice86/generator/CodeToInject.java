package spice86.generator;

import org.apache.commons.collections4.CollectionUtils;
import spice86.tools.SegmentedAddress;

import java.util.List;
import java.util.Map;

public class CodeToInject {
  private Map<SegmentedAddress, List<String>> codeToInject;

  public CodeToInject(Map<SegmentedAddress, List<String>> codeToInject) {
    this.codeToInject = codeToInject;
  }

  public List<String> getCodeToInject(SegmentedAddress address, String nextSegment,
      String nextOffset) {
    return CollectionUtils.emptyIfNull(codeToInject.get(address))
        .stream()
        .map(s -> s.replaceAll("\\{nextSegment\\}", nextSegment).replaceAll("\\{nextOffset\\}", nextOffset))
        .toList();
  }
}
