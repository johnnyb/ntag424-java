package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

import net.bplearning.ntag424.command.KeyInfo;

public class KeyInfoTest {
	@Test
	public void testKeyInfo() {
		// Example from pg. 7
		KeyInfo keyInfo = new KeyInfo();
		keyInfo.systemIdentifier = Util.hexToByte("4E585020416275");
		keyInfo.key = Util.hexToByte("00112233445566778899AABBCCDDEEFF");
		byte[] cardUid = Util.hexToByte("04782E21801D80");
		byte[] cardKey = keyInfo.generateKeyForCardUid(cardUid);
		byte[] expectedCardKey = Util.hexToByte("A8DD63A3B89D54B37CA802473FDA9175");
		assertArrayEquals("Diversified card key incorrect", cardKey, expectedCardKey);
	}
}
