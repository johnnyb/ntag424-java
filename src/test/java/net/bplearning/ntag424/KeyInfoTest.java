package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import net.bplearning.ntag424.card.KeyInfo;
import net.bplearning.ntag424.card.KeySet;

public class KeyInfoTest {
	@Test
	public void testKeyInfo() {
		// Example from pg. 7
		KeyInfo keyInfo = new KeyInfo();
		keyInfo.systemIdentifier = Util.hexToByte("4E585020416275");
		keyInfo.key = Util.hexToByte("00112233445566778899AABBCCDDEEFF");
		keyInfo.diversifyKeys = true;
		byte[] cardUid = Util.hexToByte("04782E21801D80");
		byte[] cardKey = keyInfo.generateKeyForCardUid(cardUid);
		byte[] expectedCardKey = Util.hexToByte("A8DD63A3B89D54B37CA802473FDA9175");
		assertArrayEquals("Diversified card key incorrect", cardKey, expectedCardKey);
	}

	@Test 
	public void keysetTest() {
		KeySet ks = new KeySet();
		KeyInfo ki = new KeyInfo();
		ki.diversifyKeys = true;
		ki.systemIdentifier = "McElroy".getBytes();
		ks.setKey(1, ki);
		ks.setMacFileKey(1);
		assertNotNull(ks.decodeAndVerifyPiccData("04A77F12647380", "00001C", "9A88066EBE25ECD0"));
	}
}
