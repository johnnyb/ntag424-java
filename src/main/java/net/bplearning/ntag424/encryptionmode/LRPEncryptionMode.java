package net.bplearning.ntag424.encryptionmode;

public class LRPEncryptionMode implements EncryptionMode {

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

	public void restartSession() {
		// FIXME - implement authenticateLRPNonFirst
	}
	
}
