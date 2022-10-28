package spice86.tools;

public class InvalidBitLengthException extends RuntimeException {
  public InvalidBitLengthException(int bits) {
    super("Invalid bit length: " + bits);
  }
}
