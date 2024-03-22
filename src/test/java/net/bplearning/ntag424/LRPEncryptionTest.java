package net.bplearning.ntag424;

import javax.crypto.Cipher;

import org.junit.Test;

import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.lrp.LRPMultiCipher;

public class LRPEncryptionTest {
	@Test
	public void testLRP() {
		byte[] key = Util.hexToByte("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
		byte[] rndA = Util.hexToByte("F5 37 06 6D 24 FF 8F F1 49 D9 01 2A 47 A3 6E 5A");
		byte[] rndB = Util.hexToByte("66 72 1F 1E 48 30 BA E9 E4 49 CF BF 42 D0 7E 78");
		byte[] expectedSessionKey = Util.hexToByte("2A 51 81 84 8C 63 01 58 FC 56 DF 55 1B D8 1A 6C");
		LRPMultiCipher mc = new LRPMultiCipher(key);
		byte[] sessionKey = LRPEncryptionMode.generateLRPSessionKey(mc, rndA, rndB);
		if(!Util.arraysEqual(expectedSessionKey, sessionKey)) {
			throw new RuntimeException("Unexpected session key: " + Util.byteToHex(sessionKey));
		}
		LRPEncryptionMode mode = new LRPEncryptionMode(null, mc, rndA, rndB);
		byte[] tiEncrypted = Util.hexToByte("FA E1 9D 27 82 38 CA 84 1E 37 EC EB F7 5B 0E 72");
	   byte[] tiDecrypted = mode.getSessionLrpEncryptionCipher().cryptFullBlocks(tiEncrypted, Cipher.DECRYPT_MODE);
	   byte[] expectedTiDecrypted = Util.hexToByte("2F 0C F7 91 02 00 00 00 00 00 02 00 00 00 00 00");
		if(!Util.arraysEqual(tiDecrypted, expectedTiDecrypted)) {
			throw new RuntimeException("Invalid TI decryption: " + Util.byteToHex(tiDecrypted));
		}

		byte[] cipherData = Util.hexToByte("51 00 00 2F 0C F7 91");
		byte[] longMac = mode.generateMac(cipherData);
		byte[] shortMac = Util.shortenCMAC(longMac);
		byte[] expectedShortMac = Util.hexToByte("79 00 03 E6 9F 33 0E AC");
		if(!Util.arraysEqual(expectedShortMac, shortMac)) {
			throw new RuntimeException("Bad MAC: " + Util.byteToHex(shortMac));
		}
	}
}
