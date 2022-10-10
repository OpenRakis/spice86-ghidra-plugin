package spice86.tools;

import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.InvalidInputException;

public class LabelManager extends ObjectWithContextAndLog {
  private Program program;

  public LabelManager(Context context) {
    super(context);
    this.program = context.getProgram();
  }

  public Symbol getPrimarySymbol(Address address) {
    return program.getSymbolTable().getPrimarySymbol(address);
  }

  public void createPrimaryLabel(Address address, String name) throws InvalidInputException {
    Symbol createdSymbol = program.getSymbolTable().createLabel(address, name, null, SourceType.USER_DEFINED);
    if (!createdSymbol.isPrimary()) {
      SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, name, null);
      cmd.applyTo(this.program);
    }
  }

  public void deleteAllLabels(Address address) {
    SymbolIterator symbolIterator = program.getSymbolTable().getSymbolsAsIterator(address);
    while (symbolIterator.hasNext()) {
      Symbol symbol = symbolIterator.next();
      if (symbol == null || symbol.getSymbolType() != SymbolType.LABEL) {
        continue;
      }
      log.info("Found label " + symbol.getName() + " at address " + address + ". Deleting it.");
      DeleteLabelCmd cmd = new DeleteLabelCmd(address, symbol.getName());
      cmd.applyTo(this.program);
    }
  }
}
