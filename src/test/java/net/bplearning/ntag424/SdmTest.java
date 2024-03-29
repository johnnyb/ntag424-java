package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

import net.bplearning.ntag424.lrp.LRPMultiCipher;
import net.bplearning.ntag424.sdm.PiccData;

public class SdmTest {
	@Test 
	public void testSdm() {
		byte[] uid = Util.hexToByte("04827F12647380");
		int counter = 0x07;
		byte[] key = Constants.FACTORY_KEY;

		PiccData piccData = new PiccData(uid, counter, true);
		piccData.setMacFileKey(key);
		byte[] shortMac = piccData.performShortCMAC(new byte[0]);
		byte[] expectedShortMac = Util.hexToByte("A9DAF6E5B2E583ED");
		assertArrayEquals("SDM Mac Calculation", expectedShortMac, shortMac);
	}
}
