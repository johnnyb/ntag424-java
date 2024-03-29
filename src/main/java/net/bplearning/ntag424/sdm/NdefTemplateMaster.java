package net.bplearning.ntag424.sdm;

import java.util.HashMap;
import java.util.Map;

import net.bplearning.ntag424.Constants;
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

	/**
	 * Generates an NDEF file for the card from a String template and SDMSettings.
	 * This both *uses* the SDMSettings given *and* modifies it based on the
	 * template to be sure the proper features are enabled.
	 * However, it does require that the user properly set
	 * the SDM permissions first.
	 * @param urlString
	 * @param sdmDefaults
	 * @return
	 */
	public byte[] generateNdefTemplateFromUrlString(String urlString, SDMSettings sdmDefaults) {
		byte[] ndefData = Util.ndefDataForUrlString(urlString);
		byte[] ndefRecord = generateNdefTemplateFrom(ndefData, sdmDefaults);
		ndefRecord[1] = (byte)(ndefRecord.length - 2); // New record length
		ndefRecord[4] = (byte)(ndefRecord.length - 6); // New URL length
		return ndefRecord;
	}

	/**
	 * Generally not used, but this is the internal version of
	 * generateNdefTemplateFromUrlString which operates on bytes,
	 * and assumes that the byte array is already formatted according
	 * to what is required for an NDEF file on this card. 
	 * @param recordTemplate
	 * @param sdmDefaults
	 * @return
	 */
	public byte[] generateNdefTemplateFrom(byte[] recordTemplate, SDMSettings sdmDefaults) {
		SDMSettings sdmSettings = sdmDefaults;
		byte[] record = recordTemplate;

		Map<Placeholder, byte[]> placeholderTemplates = getPlaceholderTemplate();
		Map<Placeholder, Integer> placeholderLengths = getPlaceholderLengths(sdmSettings);
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
			if (foundAt != null && foundAt != -1) {
				record = searchResult.first;
				adjustPlaceholderOffsets(placeholderOffsets, foundAt, template.length, replacement.length);
				placeholderOffsets.put(p, foundAt);
			}
			record = searchResult.first;
		}

		loadPlaceholderOffsets(sdmSettings, placeholderOffsets);		

		return record;
	} 

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

	Map<Placeholder, Integer> getPlaceholderLengths(SDMSettings settings) {
		int asciiMultiplier = settings.sdmOptionUseAscii ? 2 : 1;
		Map<Placeholder, Integer> ptemps = new HashMap<>();
		ptemps.put(Placeholder.UID, 7 * asciiMultiplier);
		ptemps.put(Placeholder.PICC, (usesLRP ? 24 : 16) * asciiMultiplier);
		ptemps.put(Placeholder.MAC, 8 * asciiMultiplier);
		ptemps.put(Placeholder.ReadCounter, 3 * asciiMultiplier);
		ptemps.put(Placeholder.FileData, Util.roundUpToMultiple(fileDataLength, 16) * asciiMultiplier);
		ptemps.put(Placeholder.MACInputOffset, 0);
		return ptemps;
	}

	void adjustPlaceholderOffsets(Map<Placeholder, Integer> offsetList, int idx, int removed, int added) {
		int adjustment = added - removed;
		for(Placeholder p: offsetList.keySet()) {
			int offset = offsetList.get(p);
			if(offset >= idx) {
				offset += adjustment;
				offsetList.put(p, offset);	
			}	
		}
	}

	void loadPlaceholderOffsets(SDMSettings sdmSettings, Map<Placeholder, Integer> offsets) {
		Integer uidOffset = offsets.get(Placeholder.UID);
		Integer piccOffset = offsets.get(Placeholder.PICC);
		Integer macOffset = offsets.get(Placeholder.MAC);
		Integer readCounterOffset = offsets.get(Placeholder.ReadCounter);
		Integer fileDataOffset = offsets.get(Placeholder.FileData);
		Integer macInputOffset = offsets.get(Placeholder.MACInputOffset);

		sdmSettings.sdmEnabled = true;

		if(uidOffset == null) {
			sdmSettings.sdmOptionUid = false;
		} else {
			sdmSettings.sdmOptionUid = true;
			sdmSettings.sdmUidOffset = uidOffset;
		}
		if(piccOffset != null) {
			sdmSettings.sdmPiccDataOffset = piccOffset;
		}
		if(macOffset != null) {
			sdmSettings.sdmMacOffset = macOffset;
		}
		if(readCounterOffset == null) {
			sdmSettings.sdmReadCounterOffset = 0xffffff;
		} else {
			sdmSettings.sdmOptionReadCounter = true;
			sdmSettings.sdmReadCounterOffset = readCounterOffset;
			sdmSettings.sdmMetaReadPerm = Constants.ACCESS_EVERYONE; // Required for reading the readcounter directly		
		}
		if(fileDataOffset == null) {
			sdmSettings.sdmOptionEncryptFileData = false;
		} else {
			sdmSettings.sdmOptionEncryptFileData = true;
			sdmSettings.sdmEncOffset = uidOffset;
			sdmSettings.sdmEncLength = fileDataLength;
		}
		if(macInputOffset == null) {
			sdmSettings.sdmMacInputOffset = sdmSettings.sdmMacOffset; // Default to zero-length (PICC-only) MAC
		} else {
			sdmSettings.sdmMacInputOffset = macInputOffset;
		}
	}
}
