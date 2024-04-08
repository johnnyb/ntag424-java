package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import net.bplearning.ntag424.lrp.LRPMultiCipher;
import net.bplearning.ntag424.sdm.PiccData;

public class SdmTest {
	@Test 
	public void testSdmLRPMac() {
		byte[] uid = Util.hexToByte("04827F12647380");
		int counter = 0x07;
		byte[] key = Constants.FACTORY_KEY;

		PiccData piccData = new PiccData(uid, counter, true);
		piccData.setMacFileKey(key);
		byte[] shortMac = piccData.performShortCMAC(new byte[0]);
		byte[] expectedShortMac = Util.hexToByte("A9DAF6E5B2E583ED");
		assertArrayEquals("SDM Mac Calculation", expectedShortMac, shortMac);
	}

	@Test
	public void testPICCEncryptionLRPNoUid() {
		byte[] encryptedPiccData = Util.hexToByte("D99C1B274606743ECE77E01D0D46CCE69F00C0C246363639");
		assertEquals(24, encryptedPiccData.length);
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, true);
		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertEquals(0x1a, piccData.getReadCounter());
		byte[] expectedMac = Util.hexToByte("15CA6F05740D1AE2");
		byte[] mac = piccData.performCMAC(new byte[0]);
		//assertArrayEquals(expectedMac, mac);
	}

	@Test
	public void testPICCEncryptionAES() {
		byte[] encryptedPiccData = Util.hexToByte("84DC15E87593037C7DDA281C2D55B8F2");
		byte[] expectedCmac = Util.hexToByte("4BBC218E7B2B36AF");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, false);
		byte[] expectedUid = Util.hexToByte("049f50824f1390");
		int expectedReadCount = 33;

		assertArrayEquals(expectedUid, piccData.getUid());
		assertEquals(expectedReadCount, piccData.getReadCounter());

		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertArrayEquals(expectedCmac, piccData.performShortCMAC(null));
	}

	@Test
	public void testPICCEncryptionLRP() {
		byte[] encryptedPiccData = Util.hexToByte("B3373525DC0343DEDB5F8E89F5387402EDFB8C22186FC129");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, true);
		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertEquals(0x1e, piccData.getReadCounter());
		assertArrayEquals(Util.hexToByte("04827F12647380"), piccData.getUid());
		byte[] shortMacData = piccData.performShortCMAC(null);		
		assertArrayEquals(Util.hexToByte("A3773D237775F892"), shortMacData);
	}

	@Test 
	public void testFileEncrpytionLRP() {
		byte[] encryptedPiccData = Util.hexToByte("4EED5D97131E60E6EA7C99DCC98FED49344896F16257DC6B");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, true);
		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertArrayEquals(Util.hexToByte("04827F12647380"), piccData.getUid());
		assertEquals(0x21, piccData.getReadCounter());
		byte[] decryptedData = piccData.decryptFileData(Util.hexToByte("0586F575D54AECF1586B1FE750E8C0AC"));
		byte[] expectedDecryptedData = Util.hexToByte("2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A");
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	public void testFileEncryption2LRP() {
		byte[] encryptedPiccData = Util.hexToByte("B3EC473AD2BDB04A0B75065B8E775FEF2D08AD7E8D024DF2");
		byte[] encryptedContent = Util.hexToByte("A8335B51B0A252AFEAFEEB38FCA0D810");
		byte[] contentForMac = "A8335B51B0A252AFEAFEEB38FCA0D810/".getBytes();
		byte[] expectedMac = Util.hexToByte("02E985A8AE05ED05");

		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, true);
		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertArrayEquals(Util.hexToByte("04827F12647380"), piccData.getUid());
		assertEquals(0x25, piccData.getReadCounter());
		byte[] decryptedData = piccData.decryptFileData(encryptedContent);
		byte[] expectedDecryptedData = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		assertArrayEquals(expectedDecryptedData, decryptedData);
		assertArrayEquals(expectedMac, piccData.performShortCMAC(contentForMac));
	}

	// Class for exposing protected methods for testing purposes
	static class PiccDataForTesting extends PiccData {
		public PiccDataForTesting(byte[] uid, int counter, boolean usesLRP) { 
			super(uid, counter, usesLRP);
		}
		
		public byte[] generateAESSessionEncKeyForTesting(byte[] key) {
			return generateAESSessionEncKey(key);
		}

		public byte[] generateAESSessionMacKeyForTesting(byte[] key) {
			return generateAESSessionMacKey(key);
		}
	}

	@Test 
	public void testSDMAESKeyGeneration() {
		// From Pg. 10 of AN12196
		byte[] uid = Util.hexToByte("04C767F2066180");
		byte[] key = Util.hexToByte("5ACE7E50AB65D5D51FD5BF5A16B8205B");
		int readCounter = 1;
		PiccDataForTesting piccData = new PiccDataForTesting(uid, readCounter, false);
		piccData.setMacFileKey(key);

		byte[] expectedEncKey = Util.hexToByte("66DA61797E23DECA5D8ECA13BBADF7A9");
		byte[] expectedMacKey = Util.hexToByte("3A3E8110E05311F7A3FCF0D969BF2B48");

		assertArrayEquals(expectedEncKey, piccData.generateAESSessionEncKeyForTesting(key));
		assertArrayEquals(expectedMacKey, piccData.generateAESSessionMacKeyForTesting(key));
	}

	@Test
	public void testFileEncryptionAESFromFeaturesHints() {
		// Pg. 14 AN12196
		byte[] encryptedData = Util.hexToByte("94592FDE69FA06E8E3B6CA686A22842B");
		byte[] uid = Util.hexToByte("04958CAA5C5E80");
		byte[] key = Constants.FACTORY_KEY;
		int readCounter = 1;
		PiccData piccData = new PiccData(uid, readCounter, false);
		piccData.setMacFileKey(key);
		byte[] decrypedData = piccData.decryptFileData(encryptedData);
		byte[] expectedDecryptedData = Util.hexToByte("78787878787878787878787878787878");
		assertArrayEquals(expectedDecryptedData, decrypedData);
	}

	@Test
	public void testFileEncryptionAES() {
		byte[] encryptedPiccData = Util.hexToByte("379F7A361ED4728A13B70F2B591FFA6B");
		byte[] encryptedContent = Util.hexToByte("A0DED1861CC740B47240AC0C944DC2EF");
		byte[] contentForMac = "A0DED1861CC740B47240AC0C944DC2EF/".getBytes();
		byte[] expectedMac = Util.hexToByte("4FF9720BC3FE5910");

		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Constants.FACTORY_KEY, false);
		piccData.setMacFileKey(Constants.FACTORY_KEY);
		assertEquals(0x01, piccData.getReadCounter());
		assertArrayEquals(Util.hexToByte("04B07F12647380"), piccData.getUid());
		byte[] decryptedData = piccData.decryptFileData(encryptedContent);
		byte[] expectedDecryptedData = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		assertArrayEquals(expectedDecryptedData, decryptedData);
		assertArrayEquals(expectedMac, piccData.performShortCMAC(contentForMac));
	}
}
