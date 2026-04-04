package spice86.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import spice86.tools.config.ExecutionFlow;
import spice86.tools.config.PluginConfiguration;

import java.util.Map;

/**
 * Translates between Spice86 runtime linear addresses and the current Ghidra program address space.
 */
public class RuntimeAddressTranslator {
  private final long addressDelta;

  public RuntimeAddressTranslator(long addressDelta) {
    this.addressDelta = addressDelta;
  }

  public static RuntimeAddressTranslator infer(Program program, PluginConfiguration pluginConfiguration) {
    SegmentedAddress runtimeEntry = findRuntimeEntry(pluginConfiguration);
    if (runtimeEntry == null) {
      return new RuntimeAddressTranslator(0);
    }
    Address programEntry = findProgramEntryPoint(program);
    if (programEntry == null) {
      return new RuntimeAddressTranslator(0);
    }
    return new RuntimeAddressTranslator(programEntry.getUnsignedOffset() - runtimeEntry.toPhysical());
  }

  private static SegmentedAddress findRuntimeEntry(PluginConfiguration pluginConfiguration) {
    for (Map.Entry<SegmentedAddress, String> entry : pluginConfiguration.getRecordedFunctions().entrySet()) {
      if (entry.getValue().startsWith("entry_")) {
        return entry.getKey();
      }
    }
    ExecutionFlow executionFlow = pluginConfiguration.getExecutionFlow();
    if (!executionFlow.getExecutedInstructions().isEmpty()) {
      return executionFlow.getExecutedInstructions().get(0);
    }
    if (!pluginConfiguration.getRecordedFunctions().isEmpty()) {
      return pluginConfiguration.getRecordedFunctions().keySet().stream().min(SegmentedAddress::compareTo).orElse(null);
    }
    return null;
  }

  private static Address findProgramEntryPoint(Program program) {
    AddressIterator iterator = program.getSymbolTable().getExternalEntryPointIterator();
    if (iterator.hasNext()) {
      return iterator.next();
    }
    Memory memory = program.getMemory();
    return memory == null ? null : memory.getMinAddress();
  }

  public long getAddressDelta() {
    return addressDelta;
  }

  public long toProgramLinear(long runtimeLinear) {
    return runtimeLinear + addressDelta;
  }

  public int toRuntimeLinear(long programLinear) {
    return (int)(programLinear - addressDelta);
  }

  public Address toProgramAddress(Program program, SegmentedAddress segmentedAddress) {
    return Utils.toAddr(program, toProgramLinear(segmentedAddress.toPhysical()));
  }

  public boolean isProgramAddressFor(Address address, SegmentedAddress segmentedAddress) {
    return address.getUnsignedOffset() == toProgramLinear(segmentedAddress.toPhysical());
  }
}
