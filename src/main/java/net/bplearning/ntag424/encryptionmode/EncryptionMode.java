package net.bplearning.ntag424.encryptionmode;

import java.io.IOException;

import net.bplearning.ntag424.DnaCommunicator;

public interface EncryptionMode {
	byte[] encryptData(byte[] message);
	byte[] decryptData(byte[] message);
	byte[] generateMac(byte[] message);
	void restartSession(DnaCommunicator comm) throws IOException;
	void restartSessionNonFirst(DnaCommunicator comm) throws IOException;
}
