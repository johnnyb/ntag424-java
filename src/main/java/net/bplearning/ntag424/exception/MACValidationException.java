package net.bplearning.ntag424.exception;

public class MACValidationException extends ProtocolException {
	public MACValidationException() {
		super("Invalid MAC");
	}
}