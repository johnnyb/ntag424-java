package net.bplearning.ntag424;

import org.junit.Test;

import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

public class NdefTemplateTest {
	@Test
	public void testNdefTemplateGeneration() {
		SDMSettings s = new SDMSettings();
		NdefTemplateMaster master = new NdefTemplateMaster();
		String url = "http://example.com/{PICC}/^{MAC}";
		byte[] ndefRecord = master.generateNdefTemplateFrom(url.getBytes(), s);
		String newUrl = new String(ndefRecord);
		if(!newUrl.equals("http://example.com/********************************/****************")) {
			throw new RuntimeException("Result: " + newUrl);
		}
	}
}
