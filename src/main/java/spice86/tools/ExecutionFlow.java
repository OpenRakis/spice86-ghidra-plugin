package spice86.tools;

import com.google.gson.annotations.SerializedName;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ExecutionFlow {
  @SerializedName("CallsFromTo") private Map<Integer, List<SegmentedAddress>> callsFromTo;
  @SerializedName("JumpsFromTo") private Map<Integer, List<SegmentedAddress>> jumpsFromTo;
  @SerializedName("RetsFromTo") private Map<Integer, List<SegmentedAddress>> retsFromTo;
  @SerializedName("ExecutableAddressWrittenBy") private Map<Integer, Map<Integer, Set<ByteModificationRecord>>>
      executableAddressWrittenBy;

  private Map<Integer, List<SegmentedAddress>> callsJumpsFromTo = new HashMap<>();
  private Set<SegmentedAddress> jumpTargets;

  public void init() {
    callsJumpsFromTo.putAll(callsFromTo);
    callsJumpsFromTo.putAll(jumpsFromTo);
    jumpTargets = jumpsFromTo.values().stream().flatMap(Collection::stream).collect(Collectors.toSet());
  }

  public Map<Integer, List<SegmentedAddress>> getCallsFromTo() {
    return callsFromTo;
  }

  public Map<Integer, List<SegmentedAddress>> getJumpsFromTo() {
    return jumpsFromTo;
  }

  public Map<Integer, List<SegmentedAddress>> getRetsFromTo() {
    return retsFromTo;
  }

  public Map<Integer, List<SegmentedAddress>> getCallsJumpsFromTo() {
    return callsJumpsFromTo;
  }

  public Set<SegmentedAddress> getJumpTargets() {
    return jumpTargets;
  }

  public Map<Integer, Map<Integer, Set<ByteModificationRecord>>> getExecutableAddressWrittenBy() {
    return executableAddressWrittenBy;
  }
}
