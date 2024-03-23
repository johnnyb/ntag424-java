package net.bplearning.ntag424.sdm;

import java.util.HashMap;
import java.util.Map;

import net.bplearning.ntag424.Pair;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.command.FileSettings;

/**
 * This class makes reading/writing NDEF data easier.
 */
public class NdefTemplateMaster {
	public byte[] placeholderUID = "{UID}".getBytes();
	public byte[] placeholderPICC = "{PICC}".getBytes();
	public byte[] placeholderMAC = "{MAC}".getBytes();
	public byte[] placeholderReadCounter = "{COUNTER}".getBytes();
	public byte[] placeholderFileData = "{FILE}".getBytes();
	public byte[] placeholderMACInputOffset = "^".getBytes();
	public byte overwriteChar = '*';
	public int fileDataLength;
	public boolean usesLRP;

	static enum Placeholder {
		UID, PICC, MAC, ReadCounter, FileData, MACInputOffset
	};

	Map<Placeholder, byte[]> getPlaceholderTemplate() {
		Map<Placeholder, byte[]> ptemps = new HashMap<>();
		ptemps.put(Placeholder.UID, placeholderUID);
		ptemps.put(Placeholder.PICC, placeholderPICC);
		ptemps.put(Placeholder.MAC, placeholderMAC);
		ptemps.put(Placeholder.ReadCounter, placeholderReadCounter);
		ptemps.put(Placeholder.FileData, placeholderFileData);
		ptemps.put(Placeholder.MACInputOffset, placeholderMACInputOffset);
		return ptemps;
	}

	Map<Placeholder, Integer> getPlaceholderLengths() {
		// FIXME - currently fake data
		Map<Placeholder, Integer> ptemps = new HashMap<>();
		ptemps.put(Placeholder.UID, 8);
		ptemps.put(Placeholder.PICC, 8);
		ptemps.put(Placeholder.MAC, 8);
		ptemps.put(Placeholder.ReadCounter, 8);
		ptemps.put(Placeholder.FileData, 8);
		ptemps.put(Placeholder.MACInputOffset, 8);
		return ptemps;
	}

	public NdefTemplate generateNdefTemplateFrom(byte[] recordTemplate, SDMSettings sdmDefaults) {
		SDMSettings sdmSettings = sdmDefaults.duplicate();
		byte[] record = recordTemplate;

		Map<Placeholder, byte[]> placeholderTemplates = getPlaceholderTemplate();
		Map<Placeholder, Integer> placeholderLengths = getPlaceholderLengths();
		Map<Placeholder, Integer> placeholderOffsets = new HashMap<>();

		for(Placeholder p: Placeholder.values()) {
			int dataLength = placeholderLengths.get(p);
			byte[] replacement = Util.generateRepeatingBytes(overwriteChar, dataLength);
			byte[] template = placeholderTemplates.get(p);
			Pair<byte[], Integer> searchResult = Util.findAndReplaceBytes(
				record, 
				template, 
				replacement
			);
			Integer foundAt = searchResult.second;
			if (foundAt != null) {
				record = searchResult.first;
				adjustPlaceholderOffsets(placeholderOffsets, foundAt, template.length, replacement.length);
				placeholderOffsets.put(p, foundAt);
			}
			record = searchResult.first;
		}

		NdefTemplate template = new NdefTemplate();
		template.ndefRecord = record;

		// FIXME - write offsets and lengths

		return template;
	} 

	void adjustPlaceholderOffsets(Map<Placeholder, Integer> offsetList, int idx, int removed, int added) {
		int adjustment = added - removed;
		for(Placeholder p: offsetList.keySet()) {
			int offset = offsetList.get(p);
			offset += adjustment;
			offsetList.put(p, offset);
		}
	}
}
