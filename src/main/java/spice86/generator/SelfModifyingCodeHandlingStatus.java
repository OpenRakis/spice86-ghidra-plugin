package spice86.generator;

import java.util.ArrayList;
import java.util.List;

public interface SelfModifyingCodeHandlingStatus {
  String OPCODE_IS_MODIFIED = "Opcode is modified";
  String PARAMETER_1_MODIFIED = "First value group is modified";
  String PARAMETER_2_MODIFIED = "Second value group is modified";
  String MODRM_MODIFIED = "Mod R/M is modified";
  String PREFIX_MODIFIED = "Prefix is modified";

  boolean isOpCodeModified();

  boolean isParameter1Modified();

  boolean isParameter2Modified();

  boolean isModRmModified();

  boolean isPrefixModified();

  default boolean isAnyHandled() {
    return isOpCodeModified() || isParameter1Modified() || isParameter2Modified();
  }

  default String generateHandledItems() {
    List<String> res = new ArrayList<>();
    if (isOpCodeModified()) {
      res.add(OPCODE_IS_MODIFIED);
    }
    if (isParameter1Modified()) {
      res.add(PARAMETER_1_MODIFIED);
    }
    if (isParameter2Modified()) {
      res.add(PARAMETER_2_MODIFIED);
    }
    if (isModRmModified()) {
      res.add(MODRM_MODIFIED);
    }
    if (isPrefixModified()) {
      res.add(PREFIX_MODIFIED);
    }
    return String.join(", ", res);
  }

  default boolean isAllHandled(SelfModifyingCodeHandlingStatus other) {
    return other.isOpCodeModified() == isOpCodeModified() && other.isParameter1Modified() == isParameter1Modified()
        && other.isParameter2Modified() == isParameter2Modified() && other.isModRmModified() == isModRmModified()
        && other.isPrefixModified() == isPrefixModified();
  }

  default boolean isAnyParameterModified() {
    return isParameter1Modified() || isParameter2Modified();
  }
}
