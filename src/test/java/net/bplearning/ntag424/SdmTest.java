package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import javax.rmi.CORBA.Util;

import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.util.ByteUtil;
import org.junit.Test;

import net.bplearning.ntag424.sdm.PiccData;

public class SdmTest {
	@Test 
	public void testSdmLRPMac() {
		byte[] uid = ByteUtil.hexToByte("04827F12647380");
		int counter = 0x07;
		byte[] key = Ntag424.FACTORY_KEY;

		PiccData piccData = new PiccData(uid, counter, true);
		piccData.setMacFileKey(key);
		byte[] shortMac = piccData.performShortCMAC(new byte[0]);
		byte[] expectedShortMac = ByteUtil.hexToByte("A9DAF6E5B2E583ED");
		assertArrayEquals("SDM Mac Calculation", expectedShortMac, shortMac);
	}

	@Test
	public void testPICCEncryptionLRPNoUid() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("D99C1B274606743ECE77E01D0D46CCE69F00C0C246363639");
		assertEquals(24, encryptedPiccData.length);
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, true);
		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertEquals(0x1a, piccData.getReadCounter());
		byte[] expectedMac = ByteUtil.hexToByte("15CA6F05740D1AE2");
		byte[] mac = piccData.performCMAC(new byte[0]);
		//assertArrayEquals(expectedMac, mac);
	}

	@Test
	public void testPICCEncryptionAES() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("84DC15E87593037C7DDA281C2D55B8F2");
		byte[] expectedCmac = ByteUtil.hexToByte("4BBC218E7B2B36AF");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, false);
		byte[] expectedUid = ByteUtil.hexToByte("049f50824f1390");
		int expectedReadCount = 33;

		assertArrayEquals(expectedUid, piccData.getUid());
		assertEquals(expectedReadCount, piccData.getReadCounter());

		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertArrayEquals(expectedCmac, piccData.performShortCMAC(null));
	}

	@Test
	public void testPICCEncryptionLRP() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("B3373525DC0343DEDB5F8E89F5387402EDFB8C22186FC129");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, true);
		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertEquals(0x1e, piccData.getReadCounter());
		assertArrayEquals(ByteUtil.hexToByte("04827F12647380"), piccData.getUid());
		byte[] shortMacData = piccData.performShortCMAC(null);		
		assertArrayEquals(ByteUtil.hexToByte("A3773D237775F892"), shortMacData);
	}

	@Test 
	public void testFileEncrpytionLRP() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("4EED5D97131E60E6EA7C99DCC98FED49344896F16257DC6B");
		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, true);
		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertArrayEquals(ByteUtil.hexToByte("04827F12647380"), piccData.getUid());
		assertEquals(0x21, piccData.getReadCounter());
		byte[] decryptedData = piccData.decryptFileData(ByteUtil.hexToByte("0586F575D54AECF1586B1FE750E8C0AC"));
		byte[] expectedDecryptedData = ByteUtil.hexToByte("2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A");
		assertArrayEquals(expectedDecryptedData, decryptedData);
	}

	@Test
	public void testFileEncryption2LRP() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("B3EC473AD2BDB04A0B75065B8E775FEF2D08AD7E8D024DF2");
		byte[] encryptedContent = ByteUtil.hexToByte("A8335B51B0A252AFEAFEEB38FCA0D810");
		byte[] contentForMac = "A8335B51B0A252AFEAFEEB38FCA0D810/".getBytes();
		byte[] expectedMac = ByteUtil.hexToByte("02E985A8AE05ED05");

		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, true);
		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertArrayEquals(ByteUtil.hexToByte("04827F12647380"), piccData.getUid());
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
		byte[] uid = ByteUtil.hexToByte("04C767F2066180");
		byte[] key = ByteUtil.hexToByte("5ACE7E50AB65D5D51FD5BF5A16B8205B");
		int readCounter = 1;
		PiccDataForTesting piccData = new PiccDataForTesting(uid, readCounter, false);
		piccData.setMacFileKey(key);

		byte[] expectedEncKey = ByteUtil.hexToByte("66DA61797E23DECA5D8ECA13BBADF7A9");
		byte[] expectedMacKey = ByteUtil.hexToByte("3A3E8110E05311F7A3FCF0D969BF2B48");

		assertArrayEquals(expectedEncKey, piccData.generateAESSessionEncKeyForTesting(key));
		assertArrayEquals(expectedMacKey, piccData.generateAESSessionMacKeyForTesting(key));
	}

	@Test
	public void testFileEncryptionAESFromFeaturesHints() {
		// Pg. 14 AN12196
		byte[] encryptedData = ByteUtil.hexToByte("94592FDE69FA06E8E3B6CA686A22842B");
		byte[] uid = ByteUtil.hexToByte("04958CAA5C5E80");
		byte[] key = Ntag424.FACTORY_KEY;
		int readCounter = 1;
		PiccData piccData = new PiccData(uid, readCounter, false);
		piccData.setMacFileKey(key);
		byte[] decrypedData = piccData.decryptFileData(encryptedData);
		byte[] expectedDecryptedData = ByteUtil.hexToByte("78787878787878787878787878787878");
		assertArrayEquals(expectedDecryptedData, decrypedData);
	}

	@Test
	public void testFileEncryptionAES() {
		byte[] encryptedPiccData = ByteUtil.hexToByte("379F7A361ED4728A13B70F2B591FFA6B");
		byte[] encryptedContent = ByteUtil.hexToByte("A0DED1861CC740B47240AC0C944DC2EF");
		byte[] contentForMac = "A0DED1861CC740B47240AC0C944DC2EF/".getBytes();
		byte[] expectedMac = ByteUtil.hexToByte("4FF9720BC3FE5910");

		PiccData piccData = PiccData.decodeFromEncryptedBytes(encryptedPiccData, Ntag424.FACTORY_KEY, false);
		piccData.setMacFileKey(Ntag424.FACTORY_KEY);
		assertEquals(0x01, piccData.getReadCounter());
		assertArrayEquals(ByteUtil.hexToByte("04B07F12647380"), piccData.getUid());
		byte[] decryptedData = piccData.decryptFileData(encryptedContent);
		byte[] expectedDecryptedData = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		assertArrayEquals(expectedDecryptedData, decryptedData);
		assertArrayEquals(expectedMac, piccData.performShortCMAC(contentForMac));
	}

	@Test
	public void testFileDecryptionAes() {
		String scannedValue = "https://sdm.nfcdeveloper.com/tag?picc_data=4E8D0223F8C17CDCCE5BC24076CFAA0D&enc=B56FED7FF7B23791C0684F17E117C97450723BB5C104E809C8929F0264CB99F9969D07FC32BB2D11995AEF826E355097&cmac=5FD76DE4BD942DFC";
		int encOffset = 80;
		int piccOffset = 43;
		int macOffset = 182;
		String piccSubstring = scannedValue.substring(piccOffset, piccOffset + 32);
		PiccData decryptedPiccData = PiccData.decodeFromEncryptedBytes(ByteUtil.hexToByte(piccSubstring), Ntag424.FACTORY_KEY, false);
		decryptedPiccData.setMacFileKey(Ntag424.FACTORY_KEY);

		assertEquals("049F50824F1390", decryptedPiccData.getUidString());
		assertEquals(16, decryptedPiccData.getReadCounter());
		byte[] decryptedBytes = decryptedPiccData.decryptFileData(ByteUtil.hexToByte(scannedValue.substring(encOffset, encOffset + 96)));
		String decryptedValue = new String(decryptedBytes, StandardCharsets.UTF_8);
		assertEquals("19.05.2024 12:22:33#1234************************", decryptedValue);

		String valueToMac = scannedValue.substring(encOffset, macOffset);
		byte[] mac = decryptedPiccData.performShortCMAC(valueToMac.getBytes(StandardCharsets.UTF_8));
		assertEquals("5FD76DE4BD942DFC", ByteUtil.byteToHex(mac));
	}
}
