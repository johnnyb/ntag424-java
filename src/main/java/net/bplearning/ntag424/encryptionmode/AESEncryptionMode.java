package net.bplearning.ntag424.encryptionmode;

import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.DnaCommunicator;

public class AESEncryptionMode implements EncryptionMode {
	protected DnaCommunicator communicator;
	protected SecretKeySpec key;
	protected byte[] rndA;
	protected byte[] rndB;
	public AESEncryptionMode(DnaCommunicator communicator, SecretKeySpec key, byte[] rndA, byte[] rndB) {
		this.communicator = communicator;
		this.key = key;
		this.rndA = rndA;
		this.rndB = rndB;
	}

	@Override
	public byte[] encryptData(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'encryptData'");
	}

	@Override
	public byte[] decryptData(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'decryptData'");
	}

	@Override
	public byte[] generateMac(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'generateMac'");
	}
	
}
