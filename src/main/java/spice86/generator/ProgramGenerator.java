package spice86.generator;

import spice86.generator.parsing.ParsedFunction;
import spice86.generator.parsing.ParsedProgram;
import spice86.tools.Context;
import spice86.tools.Log;
import spice86.tools.SegmentedAddress;
import spice86.tools.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProgramGenerator {
  private final Context context;
  private final Log log;
  private final ParsedProgram parsedProgram;
  private final String namespace;
  // too many lines in one file makes C# IDEs very slow
  private static final int MAXIMUM_CHARACTERS_PER_CSHARP_FILE = 160000;

  public ProgramGenerator(Context context, ParsedProgram parsedProgram, String namespace) {
    this.context = context;
    this.log = context.getLog();
    this.parsedProgram = parsedProgram;
    this.namespace = namespace;
  }

  public List<String> outputCSharpFiles() {
    List<String> res = new ArrayList<>();
    boolean firstFile = true;
    StringBuilder fileContent = generateCSharpClassHeaderAndDefinition(firstFile);
    fileContent.append(Utils.indent(generateSegmentStorage(), 2));
    fileContent.append("\n");
    fileContent.append(Utils.indent(generateConstructor(), 2));
    Collection<ParsedFunction> parsedFunctions = parsedProgram.getEntryPoints().values();
    fileContent.append(Utils.indent(generateOverrideDefinitionFunction(parsedFunctions), 2) + "\n");
    fileContent.append(Utils.indent(generateCodeRewriteDetector(), 2));
    fileContent.append('\n');
    fileContent.append(Utils.indent(generateCompatibilityHelpers(), 2));
    fileContent.append('\n');
    Iterator<String> functionInterator = generateFunctions(parsedFunctions).iterator();
    if (!functionInterator.hasNext()) {
      closeFileContentAndAddToList(fileContent, res);
      return res;
    }
    while (functionInterator.hasNext()) {
      fileContent.append(functionInterator.next());
      if (!functionInterator.hasNext() || fileContent.length() >= MAXIMUM_CHARACTERS_PER_CSHARP_FILE) {
        closeFileContentAndAddToList(fileContent, res);
        firstFile = false;
        fileContent = generateCSharpClassHeaderAndDefinition(firstFile);
      }
    }
    return res;
  }

  private void closeFileContentAndAddToList(StringBuilder fileContent, List<String> files) {
    fileContent.append("}\n");
    files.add(fileContent.toString());
  }

  private StringBuilder generateCSharpClassHeaderAndDefinition(boolean includeSupplier) {
    StringBuilder additionalFile = new StringBuilder();
    additionalFile.append(generateImports());
    additionalFile.append(generateNamespace());
    if (includeSupplier) {
      additionalFile.append(generateOverrideSupplierClass());
      additionalFile.append('\n');
    }
    additionalFile.append(generateClassDeclaration());
    additionalFile.append("\n");
    return additionalFile;
  }

  private String generateNamespace() {
    return "namespace " + namespace + ";\n\n";
  }

  private String generateImports() {
    return """
        using System;
        using System.Collections.Generic;
        using Spice86.Core.CLI;
        using Spice86.Core.Emulator.Function;
        using Spice86.Core.Emulator.ReverseEngineer;
        using Spice86.Core.Emulator.VM;
        using Spice86.Shared.Emulator.Memory;
        using Spice86.Shared.Interfaces;
        using Spice86.Shared.Utils;

        """;
  }

  private String generateOverrideSupplierClass() {
    return """
        public class GeneratedOverrideSupplier : IOverrideSupplier {
          public IDictionary<SegmentedAddress, FunctionInformation> GenerateFunctionInformations(
              ILoggerService loggerService,
              Configuration configuration,
              ushort programStartAddress,
              Machine machine) {
            Dictionary<SegmentedAddress, FunctionInformation> functionInformations = new();
            _ = new GeneratedOverrides(functionInformations, machine, loggerService, configuration, programStartAddress);
            return functionInformations;
          }
        }

        """;
  }

  private String generateClassDeclaration() {
    return "public partial class GeneratedOverrides : CSharpOverrideHelper {\n";
  }

  private String generateConstructor() {
    String res =
        "public GeneratedOverrides(Dictionary<SegmentedAddress, FunctionInformation> functionInformations, Machine machine, ILoggerService loggerService, Configuration configuration, ushort entrySegment = "
            + Utils.toHexWith0X(parsedProgram.getCs1Physical() / 0x10)
            + ") : base(functionInformations, machine, loggerService, configuration) {\n";
    res += Utils.indent(generateSegmentConstructorAssignment(), 2);
    res += '\n';
    res += "  DefineGeneratedCodeOverrides();\n";
    res += "  DetectCodeRewrites();\n";
    res += "  SetProvidedInterruptHandlersAsOverridden();\n";
    res += "}\n\n";
    return res;
  }

  private String generateOverrideDefinitionFunction(Collection<ParsedFunction> functions) {
    StringBuilder res = new StringBuilder("public void DefineGeneratedCodeOverrides() {\n");
    int lastSegment = 0;

    for (ParsedFunction parsedFunction : functions) {
      String name = parsedFunction.getName();
      SegmentedAddress address = parsedFunction.getEntrySegmentedAddress();
      int currentSegment = address.getSegment();
      if (currentSegment != lastSegment) {
        lastSegment = currentSegment;
        res.append("  // " + Utils.toHexWith0X(currentSegment) + "\n");
      }
      res.append(
          "  DefineFunction(" + parsedProgram.getCodeSegmentVariables().get(currentSegment) + ", "
              + Utils.toHexWith0X(
              address.getOffset()) + ", " + name + ", false);");
      res.append('\n');
    }
    res.append("}\n\n");
    return res.toString();
  }

  private String generateSegmentConstructorAssignment() {
    return "// Observed cs1 address at generation time is " + Utils.toHexWith0X(parsedProgram.getCs1Physical() / 0x10)
        + ". Do not set entrySegment to something else if the program is not relocatable.\n" + generateSegmentVars(
        e -> "this." + e.getValue() + " = (ushort)(entrySegment + " + Utils.toHexWith0X(
            e.getKey() - parsedProgram.getCs1Physical() / 0x10) + ");\n");
  }

  private String generateSegmentStorage() {
    return generateSegmentVars(
        v -> "protected ushort " + v.getValue() + "; // " + Utils.toHexWith0X(v.getKey()) + "\n");
  }

  private String generateSegmentVars(java.util.function.Function<Map.Entry<Integer, String>, String> mapper) {
    return parsedProgram.getCodeSegmentVariables()
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(Map.Entry::getValue))
        .map(mapper)
        .collect(Collectors.joining(""));
  }

  private List<String> generateFunctions(Collection<ParsedFunction> functions) {
    List<String> list = new ArrayList<>();
    for (ParsedFunction parsedFunction : functions) {
      String funcStr =
          Utils.indent(new FunctionGenerator(context, parsedProgram, parsedFunction).outputCSharp(), 2)
              + '\n';
      list.add(funcStr);
    }
    return list;
  }

  private String generateCodeRewriteDetector() {
    StringBuilder res = new StringBuilder("public void DetectCodeRewrites() {\n");
    List<Integer> codeAddresses = parsedProgram.getInstructionAddresses().stream().sorted().toList();
    if (!codeAddresses.isEmpty()) {
      int rangeStart = codeAddresses.get(0);
      for (int i = 0; i < codeAddresses.size(); i++) {
        int currentAddress = codeAddresses.get(i);
        int currentInstructionLength = parsedProgram.getInstructionAtAddress(currentAddress).getInstructionLength();
        if (i == codeAddresses.size() - 1) {
          // Last instruction
          res.append(defineExecutableArea(rangeStart, currentAddress + currentInstructionLength - 1));
        } else {
          int actualNextAddress = codeAddresses.get(i + 1);
          int expectedNextAddress = currentAddress + currentInstructionLength;
          if (expectedNextAddress != actualNextAddress) {
            // end of range
            res.append(defineExecutableArea(rangeStart, expectedNextAddress - 1));
            rangeStart = actualNextAddress;
          }
        }
      }
    }
    res.append("}\n\n");
    return res.toString();
  }

  private String generateCompatibilityHelpers() {
    return """
        private LegacyCpuCompat Cpu => new(this);
        private LegacyAluCompat Alu => new(this);
        private new GeneratedStackCompat Stack => new(base.Stack);

        private sealed class GeneratedStackCompat(global::Spice86.Core.Emulator.CPU.Stack stack) {
          public void Push8(byte value) => stack.Push16((ushort)(short)(sbyte)value);
          public void Push16(ushort value) => stack.Push16(value);
          public void Push32(uint value) => stack.Push32(value);
          public ushort Pop16() => stack.Pop16();
          public uint Pop32() => stack.Pop32();
        }

        private sealed class LegacyCpuCompat(GeneratedOverrides owner) {
          public void Aaa() {
            bool finalAuxillaryFlag = false;
            bool finalCarryFlag = false;
            if ((owner.AL & 0x0F) > 9 || owner.AuxiliaryFlag) {
              owner.AX = (ushort)(owner.AX + 0x106);
              finalAuxillaryFlag = true;
              finalCarryFlag = true;
            }

            owner.AL = (byte)(owner.AL & 0x0F);
            owner.Alu8.UpdateFlags(owner.AL);
            owner.AuxiliaryFlag = finalAuxillaryFlag;
            owner.CarryFlag = finalCarryFlag;
          }

          public void Aad(byte value) {
            owner.AL = (byte)(owner.AL + (owner.AH * value));
            owner.AH = 0;
            owner.Alu8.UpdateFlags(owner.AL);
            owner.CarryFlag = false;
            owner.AuxiliaryFlag = false;
            owner.OverflowFlag = false;
          }

          public void Aam(byte value) {
            if (value == 0) {
              throw new global::Spice86.Core.Emulator.CPU.Exceptions.CpuDivisionErrorException("Division by zero");
            }

            byte result = (byte)(owner.AL % value);
            owner.AH = (byte)(owner.AL / value);
            owner.AL = result;
            owner.Alu8.UpdateFlags(result);
          }

          public void Aas() {
            bool finalAuxillaryFlag = false;
            bool finalCarryFlag = false;
            if ((owner.AL & 0x0F) > 9 || owner.AuxiliaryFlag) {
              owner.AX = (ushort)(owner.AX - 6);
              owner.AH = (byte)(owner.AH - 1);
              finalAuxillaryFlag = true;
              finalCarryFlag = true;
            }

            owner.AL = (byte)(owner.AL & 0x0F);
            owner.Alu8.UpdateFlags(owner.AL);
            owner.AuxiliaryFlag = finalAuxillaryFlag;
            owner.CarryFlag = finalCarryFlag;
          }

          public void Daa() {
            byte initialAL = owner.AL;
            bool initialCF = owner.CarryFlag;
            bool finalAuxillaryFlag = false;
            if ((owner.AL & 0x0F) > 9 || owner.AuxiliaryFlag) {
              owner.AL = (byte)(owner.AL + 6);
              finalAuxillaryFlag = true;
            }

            bool finalCarryFlag;
            if (initialAL > 0x99 || initialCF) {
              owner.AL = (byte)(owner.AL + 0x60);
              finalCarryFlag = true;
            } else {
              finalCarryFlag = false;
            }

            owner.Alu8.UpdateFlags(owner.AL);
            owner.AuxiliaryFlag = finalAuxillaryFlag;
            owner.CarryFlag = finalCarryFlag;
          }

          public void Das() {
            byte initialAL = owner.AL;
            bool initialCF = owner.CarryFlag;
            bool finalAuxillaryFlag = false;
            bool finalCarryFlag = false;
            owner.CarryFlag = false;
            if ((owner.AL & 0x0F) > 9 || owner.AuxiliaryFlag) {
              owner.AL = (byte)(owner.AL - 6);
              finalCarryFlag = owner.CarryFlag || initialCF;
              finalAuxillaryFlag = true;
            }

            if (initialAL > 0x99 || initialCF) {
              owner.AL = (byte)(owner.AL - 0x60);
              finalCarryFlag = true;
            }

            owner.Alu8.UpdateFlags(owner.AL);
            owner.AuxiliaryFlag = finalAuxillaryFlag;
            owner.CarryFlag = finalCarryFlag;
          }

          public byte In8(ushort port) => owner.Machine.IoPortDispatcher.ReadByte(port);
          public ushort In16(ushort port) => owner.Machine.IoPortDispatcher.ReadWord(port);
          public uint In32(ushort port) => owner.Machine.IoPortDispatcher.ReadDWord(port);
          public void Out8(ushort port, byte value) => owner.Machine.IoPortDispatcher.WriteByte(port, value);
          public void Out16(ushort port, ushort value) => owner.Machine.IoPortDispatcher.WriteWord(port, value);
          public void Out32(ushort port, uint value) => owner.Machine.IoPortDispatcher.WriteDWord(port, value);
        }

        private sealed class LegacyAluCompat(GeneratedOverrides owner) {
          public byte Adc8(byte left, byte right) => owner.Alu8.Adc(left, right);
          public ushort Adc16(ushort left, ushort right) => owner.Alu16.Adc(left, right);
          public uint Adc32(uint left, uint right) => owner.Alu32.Adc(left, right);
          public byte Add8(byte left, byte right) => owner.Alu8.Add(left, right);
          public ushort Add16(ushort left, ushort right) => owner.Alu16.Add(left, right);
          public uint Add32(uint left, uint right) => owner.Alu32.Add(left, right);
          public byte And8(byte left, byte right) => owner.Alu8.And(left, right);
          public ushort And16(ushort left, ushort right) => owner.Alu16.And(left, right);
          public uint And32(uint left, uint right) => owner.Alu32.And(left, right);
          public byte Dec8(byte value) => owner.Alu8.Dec(value);
          public ushort Dec16(ushort value) => owner.Alu16.Dec(value);
          public uint Dec32(uint value) => owner.Alu32.Dec(value);
          public byte? Div8(ushort dividend, byte divisor) => Divide(() => owner.Alu8.Div(dividend, divisor));
          public ushort? Div16(uint dividend, ushort divisor) => Divide(() => owner.Alu16.Div(dividend, divisor));
          public uint? Div32(ulong dividend, uint divisor) => Divide(() => owner.Alu32.Div(dividend, divisor));
          public sbyte? IDiv8(short dividend, sbyte divisor) => Divide(() => owner.Alu8.Idiv(dividend, divisor));
          public short? IDiv16(int dividend, short divisor) => Divide(() => owner.Alu16.Idiv(dividend, divisor));
          public int? IDiv32(long dividend, int divisor) => Divide(() => owner.Alu32.Idiv(dividend, divisor));
          public short Imul8(byte left, byte right) => owner.Alu8.Imul((sbyte)left, (sbyte)right);
          public short Imul8(sbyte left, sbyte right) => owner.Alu8.Imul(left, right);
          public int Imul16(ushort left, ushort right) => owner.Alu16.Imul((short)left, (short)right);
          public int Imul16(short left, short right) => owner.Alu16.Imul(left, right);
          public long Imul32(uint left, uint right) => owner.Alu32.Imul((int)left, (int)right);
          public long Imul32(int left, int right) => owner.Alu32.Imul(left, right);
          public byte Inc8(byte value) => owner.Alu8.Inc(value);
          public ushort Inc16(ushort value) => owner.Alu16.Inc(value);
          public uint Inc32(uint value) => owner.Alu32.Inc(value);
          public ushort Mul8(byte left, byte right) => owner.Alu8.Mul(left, right);
          public uint Mul16(ushort left, ushort right) => owner.Alu16.Mul(left, right);
          public ulong Mul32(uint left, uint right) => owner.Alu32.Mul(left, right);
          public byte Or8(byte left, byte right) => owner.Alu8.Or(left, right);
          public ushort Or16(ushort left, ushort right) => owner.Alu16.Or(left, right);
          public uint Or32(uint left, uint right) => owner.Alu32.Or(left, right);
          public byte Rcl8(byte value, int count) => owner.Alu8.Rcl(value, (byte)count);
          public ushort Rcl16(ushort value, int count) => owner.Alu16.Rcl(value, (byte)count);
          public uint Rcl32(uint value, int count) => owner.Alu32.Rcl(value, (byte)count);
          public byte Rcr8(byte value, int count) => owner.Alu8.Rcr(value, count);
          public ushort Rcr16(ushort value, int count) => owner.Alu16.Rcr(value, count);
          public uint Rcr32(uint value, int count) => owner.Alu32.Rcr(value, count);
          public byte Rol8(byte value, int count) => owner.Alu8.Rol(value, (byte)count);
          public ushort Rol16(ushort value, int count) => owner.Alu16.Rol(value, (byte)count);
          public uint Rol32(uint value, int count) => owner.Alu32.Rol(value, (byte)count);
          public byte Ror8(byte value, int count) => owner.Alu8.Ror(value, count);
          public ushort Ror16(ushort value, int count) => owner.Alu16.Ror(value, count);
          public uint Ror32(uint value, int count) => owner.Alu32.Ror(value, count);
          public byte Sar8(byte value, int count) => owner.Alu8.Sar(value, count);
          public ushort Sar16(ushort value, int count) => owner.Alu16.Sar(value, count);
          public uint Sar32(uint value, int count) => owner.Alu32.Sar(value, count);
          public byte Sbb8(byte left, byte right) => owner.Alu8.Sbb(left, right);
          public ushort Sbb16(ushort left, ushort right) => owner.Alu16.Sbb(left, right);
          public uint Sbb32(uint left, uint right) => owner.Alu32.Sbb(left, right);
          public byte Shl8(byte value, int count) => owner.Alu8.Shl(value, count);
          public ushort Shl16(ushort value, int count) => owner.Alu16.Shl(value, count);
          public uint Shl32(uint value, int count) => owner.Alu32.Shl(value, count);
          public byte Shr8(byte value, int count) => owner.Alu8.Shr(value, count);
          public ushort Shr16(ushort value, int count) => owner.Alu16.Shr(value, count);
          public uint Shr32(uint value, int count) => owner.Alu32.Shr(value, count);
          public byte Sub8(byte left, byte right) => owner.Alu8.Sub(left, right);
          public ushort Sub16(ushort left, ushort right) => owner.Alu16.Sub(left, right);
          public uint Sub32(uint left, uint right) => owner.Alu32.Sub(left, right);
          public byte Xor8(byte left, byte right) => owner.Alu8.Xor(left, right);
          public ushort Xor16(ushort left, ushort right) => owner.Alu16.Xor(left, right);
          public uint Xor32(uint left, uint right) => owner.Alu32.Xor(left, right);

          private static T? Divide<T>(Func<T> operation) where T : struct {
            try {
              return operation();
            } catch (global::Spice86.Core.Emulator.CPU.Exceptions.CpuDivisionErrorException) {
              return null;
            }
          }
        }

        private void DefineExecutableArea(uint startAddress, uint endAddress) {
          for (uint address = startAddress; address <= endAddress; address++) {
            uint addressCopy = address;
            ushort segment = (ushort)(addressCopy >> 4);
            ushort offset = (ushort)(addressCopy & 0xF);
            DoOnMemoryWrite(segment, offset,
                () => _loggerService.Warning("Write detected in generated executable area at {PhysicalAddress:X5}", addressCopy));
          }
        }
        """;
  }

  private String defineExecutableArea(int rangeStart, int rangeEnd) {
    return "  DefineExecutableArea(" + Utils.toHexWith0X(rangeStart) + ", " + Utils.toHexWith0X(rangeEnd) + ");\n";
  }
}
