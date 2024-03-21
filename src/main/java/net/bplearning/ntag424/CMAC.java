package net.bplearning.ntag424;

public interface CMAC {
	byte[] perform(byte[] message, int length);
}
