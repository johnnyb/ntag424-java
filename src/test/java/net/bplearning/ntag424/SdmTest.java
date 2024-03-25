package net.bplearning.ntag424;

import org.junit.Test;

import net.bplearning.ntag424.lrp.LRPMultiCipher;
import net.bplearning.ntag424.sdm.PiccData;

public class SdmTest {
	@Test 
	public void testSdm() {
		byte[] uid = Util.hexToByte("04827F12647380");
		int counter = 0x07;
		byte[] key = Constants.FACTORY_KEY;

		PiccData piccData = new PiccData();
		piccData.readCounter = counter;
		piccData.uid = uid;
		CMAC cmac = piccData.generateLRPCMAC(key);
		byte[] mac = cmac.perform(new byte[0], 16);
		byte[] shortMac = Util.shortenCMAC(mac);
		byte[] expectedShortMac = Util.hexToByte("A9DAF6E5B2E583ED");
		if(!Util.arraysEqual(expectedShortMac, shortMac)) {
			throw new RuntimeException("Wrong short MAC: " + Util.byteToHex(shortMac) + " (expected " + Util.byteToHex(expectedShortMac) + ")");
		}
	}
}
