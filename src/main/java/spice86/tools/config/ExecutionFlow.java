package spice86.tools.config;

import com.google.gson.annotations.SerializedName;
import spice86.tools.SegmentedAddress;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ExecutionFlow {
  @SerializedName("CallsFromTo") private Map<Integer, List<SegmentedAddress>> callsFromTo;
  @SerializedName("JumpsFromTo") private Map<Integer, List<SegmentedAddress>> jumpsFromTo;
  @SerializedName("RetsFromTo") private Map<Integer, List<SegmentedAddress>> retsFromTo;
  @SerializedName("ExecutedInstructions") private List<SegmentedAddress> executedInstructions;
  @SerializedName("ExecutableAddressWrittenBy") private Map<Integer, Map<Integer, Set<ByteModificationRecord>>>
      executableAddressWrittenBy;

  private Map<Integer, List<SegmentedAddress>> callsJumpsFromTo = new HashMap<>();
  private Set<SegmentedAddress> jumpTargets = Collections.emptySet();

  public void init() {
    callsJumpsFromTo = new HashMap<>();
    callsFromTo = nonNullMap(callsFromTo);
    jumpsFromTo = nonNullMap(jumpsFromTo);
    retsFromTo = nonNullMap(retsFromTo);
    executableAddressWrittenBy = nonNullMap(executableAddressWrittenBy);
    if (executedInstructions == null) {
      executedInstructions = new ArrayList<>();
    }
    callsJumpsFromTo.putAll(callsFromTo);
    callsJumpsFromTo.putAll(jumpsFromTo);
    jumpTargets = jumpsFromTo.values().stream().flatMap(Collection::stream).collect(Collectors.toSet());
  }

  private static <K, V> Map<K, V> nonNullMap(Map<K, V> value) {
    return value == null ? new HashMap<>() : value;
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

  public List<SegmentedAddress> getExecutedInstructions() {
    return executedInstructions;
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
