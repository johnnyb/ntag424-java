package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;

import javax.crypto.Cipher;

import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;
import org.junit.Test;

import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.lrp.LRPMultiCipher;

public class LRPEncryptionTest {
	@Test
	public void testLRP() {
		byte[] key = ByteUtil.hexToByte("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
		byte[] rndA = ByteUtil.hexToByte("F5 37 06 6D 24 FF 8F F1 49 D9 01 2A 47 A3 6E 5A");
		byte[] rndB = ByteUtil.hexToByte("66 72 1F 1E 48 30 BA E9 E4 49 CF BF 42 D0 7E 78");
		byte[] expectedSessionKey = ByteUtil.hexToByte("2A 51 81 84 8C 63 01 58 FC 56 DF 55 1B D8 1A 6C");
		LRPMultiCipher mc = new LRPMultiCipher(key);
		byte[] sessionKey = LRPEncryptionMode.generateLRPSessionKey(mc, rndA, rndB);
		if(!ByteUtil.arraysEqual(expectedSessionKey, sessionKey)) {
			throw new RuntimeException("Unexpected session key: " + ByteUtil.byteToHex(sessionKey));
		}
		LRPEncryptionMode mode = new LRPEncryptionMode(null, mc, rndA, rndB);
		byte[] tiEncrypted = ByteUtil.hexToByte("FA E1 9D 27 82 38 CA 84 1E 37 EC EB F7 5B 0E 72");
	   byte[] tiDecrypted = mode.getSessionLrpEncryptionCipher().cryptFullBlocks(tiEncrypted, Cipher.DECRYPT_MODE);
	   byte[] expectedTiDecrypted = ByteUtil.hexToByte("2F 0C F7 91 02 00 00 00 00 00 02 00 00 00 00 00");
	   assertArrayEquals("Error decrypting TI", expectedTiDecrypted, tiDecrypted);

		byte[] cipherData = ByteUtil.hexToByte("51 00 00 2F 0C F7 91");
		byte[] longMac = mode.generateMac(cipherData);
		byte[] shortMac = Crypto.shortenCMAC(longMac);
		byte[] expectedShortMac = ByteUtil.hexToByte("79 00 03 E6 9F 33 0E AC");
		assertArrayEquals("MAC error", expectedShortMac, shortMac);
	}
}
