package net.bplearning.ntag424.encryptionmode;

public interface EncryptionMode {
	byte[] encryptData(byte[] message);
	byte[] decryptData(byte[] message);
	byte[] generateMac(byte[] message);
	void restartSession();
}
