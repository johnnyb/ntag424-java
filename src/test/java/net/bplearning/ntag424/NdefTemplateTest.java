package net.bplearning.ntag424;

import org.junit.Test;

import net.bplearning.ntag424.sdm.NdefTemplate;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

public class NdefTemplateTest {
	@Test
	public void testNdefTemplateGeneration() {
		SDMSettings s = new SDMSettings();
		NdefTemplateMaster master = new NdefTemplateMaster();
		String url = "http://example.com/{PICC}/^{MAC}";
		NdefTemplate t = master.generateNdefTemplateFrom(url.getBytes(), s);
		String newUrl = new String(t.ndefRecord);
		if(!newUrl.equals("http://example.com/********************************/****************")) {
			throw new RuntimeException("Result: " + newUrl);
		}
	}
}
