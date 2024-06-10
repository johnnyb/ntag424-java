package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import net.bplearning.ntag424.util.ByteUtil;
import org.junit.Test;

import net.bplearning.ntag424.card.KeyInfo;
import net.bplearning.ntag424.card.KeySet;

public class KeyInfoTest {
	@Test
	public void testKeyInfo() {
		// Example from pg. 7
		KeyInfo keyInfo = new KeyInfo();
		keyInfo.systemIdentifier = ByteUtil.hexToByte("4E585020416275");
		keyInfo.key = ByteUtil.hexToByte("00112233445566778899AABBCCDDEEFF");
		keyInfo.diversifyKeys = true;
		byte[] cardUid = ByteUtil.hexToByte("04782E21801D80");
		byte[] cardKey = keyInfo.generateKeyForCardUid(cardUid);
		byte[] expectedCardKey = ByteUtil.hexToByte("A8DD63A3B89D54B37CA802473FDA9175");
		assertArrayEquals("Diversified card key incorrect", cardKey, expectedCardKey);
	}

	@Test 
	public void testKey192() {
		KeyInfo keyInfo = new KeyInfo();
		keyInfo.systemIdentifier = ByteUtil.hexToByte("4E585020416275");
		keyInfo.key = ByteUtil.hexToByte("00112233445566778899AABBCCDDEEFF0102030405060708");
		keyInfo.diversifyKeys = true;
		byte[] cardUid = ByteUtil.hexToByte("04782E21801D80");
		byte[] cardKey = keyInfo.generateKeyForCardUid(cardUid);
		byte[] expectedCardKey = ByteUtil.hexToByte("CE39C8E1CD82D9A7BEDBE9D74AF59B23176755EE7586E12C");
		assertArrayEquals("Diversified card key incorrect", cardKey, expectedCardKey);
	}

	@Test 
	public void testKey256() {
		KeyInfo keyInfo = new KeyInfo();
		keyInfo.systemIdentifier = ByteUtil.hexToByte("4E585020416275");
		keyInfo.key = ByteUtil.hexToByte("00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F00");
		keyInfo.diversifyKeys = true;
		byte[] cardUid = ByteUtil.hexToByte("04782E21801D80");
		byte[] cardKey = keyInfo.generateKeyForCardUid(cardUid);
		byte[] expectedCardKey = ByteUtil.hexToByte("4FC6EEC820B4C54314990B8611662DB695E7880982C0001E6067488346100AED");
		assertArrayEquals("Diversified card key incorrect", cardKey, expectedCardKey);
	}
}
