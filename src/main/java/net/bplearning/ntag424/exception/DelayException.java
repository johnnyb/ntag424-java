package net.bplearning.ntag424.exception;

public class DelayException extends ProtocolException {
	public DelayException() {
		super("Delay error received");
	}	
}
