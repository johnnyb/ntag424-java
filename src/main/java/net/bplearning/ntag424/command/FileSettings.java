package net.bplearning.ntag424.command;

import java.util.ArrayList;
import java.util.List;

import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.sdm.SDMSettings;

public class FileSettings {
	public static int SDM_READ_COUNTER_NO_MIRRORING = 16777215;

	// General Permissions
    public CommunicationMode commMode = CommunicationMode.PLAIN;
    public int readPerm = 0xe;
    public int writePerm = 0xe;
    public int readWritePerm = 0xe;
    public int changePerm = 0xe;

	// File Details
	public int fileSize = 0;

	// SDM 
	public SDMSettings sdmSettings = new SDMSettings();
	
	public static FileSettings decodeFromData(byte[] data) {
		FileSettings settings = new FileSettings();

		byte fileType = data[0];
		byte options = data[1];
		settings.sdmSettings.sdmEnabled = Util.getBitLSB(options, 6);

		// Pg. 13
		if(Util.getBitLSB(options, 1)) {
			if(Util.getBitLSB(options, 0)) {
				settings.commMode = CommunicationMode.FULL;
			}
		} else {
			if(Util.getBitLSB(options, 0)) {
				settings.commMode = CommunicationMode.MAC;
			}
		}

		// Access rights - pg. 11
		settings.readPerm = Util.leftNibble(data[3]);
		settings.writePerm = Util.rightNibble(data[3]);
		settings.readWritePerm = Util.leftNibble(data[2]);
		settings.changePerm = Util.rightNibble(data[2]);

		settings.fileSize = Util.lsbBytesToInt(Util.subArrayOf(data, 4, 3));
		int currOffset = 7;

		if(settings.sdmSettings.sdmEnabled) {
			byte sdmOptions = data[currOffset];
			currOffset++;
			settings.sdmSettings.sdmOptionUid = Util.getBitLSB(sdmOptions, 7);
			settings.sdmSettings.sdmOptionReadCounter = Util.getBitLSB(sdmOptions, 6);
			settings.sdmSettings.sdmOptionReadCounterLimit = Util.getBitLSB(sdmOptions, 5);
			settings.sdmSettings.sdmOptionEncryptFileData = Util.getBitLSB(sdmOptions, 4);
			settings.sdmSettings.sdmOptionUseAscii = Util.getBitLSB(sdmOptions, 0);

			byte sdmAccessRights1 = data[currOffset];
			currOffset++;
			byte sdmAccessRights2 = data[currOffset];
			currOffset++;
			settings.sdmSettings.sdmMetaReadPerm = Util.leftNibble(sdmAccessRights1);
			settings.sdmSettings.sdmFileReadPerm = Util.rightNibble(sdmAccessRights1);
			settings.sdmSettings.sdmReadCounterRetrievalPerm = Util.rightNibble(sdmAccessRights2);

			if(settings.sdmSettings.sdmMetaReadPerm == 0xe) {
				if (settings.sdmSettings.sdmOptionUid) {
					settings.sdmSettings.sdmUidOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
				if (settings.sdmSettings.sdmOptionReadCounter) {
					settings.sdmSettings.sdmReadCounterOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
			}

			if(settings.sdmSettings.sdmMetaReadPerm >= 0 && settings.sdmSettings.sdmMetaReadPerm <= 4) {
				settings.sdmSettings.sdmPiccDataOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmSettings.sdmFileReadPerm != 0x0f) {
				settings.sdmSettings.sdmMacInputOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;

				if(settings.sdmSettings.sdmOptionEncryptFileData) {
					settings.sdmSettings.sdmEncOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;

					settings.sdmSettings.sdmEncLength = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}

				settings.sdmSettings.sdmMacOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmSettings.sdmOptionReadCounterLimit) {
				settings.sdmSettings.sdmReadCounterLimit = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}
		}

		return settings;
	}

	public byte[] encodeToData() {
		  // Pg. 65
		  List<Byte> data = new ArrayList<>(20);

		  FileSettings settings = this; // I copied this from a different class, so this makes the copy/pasting a lot easier
  
		  int fileOption = Util.lsbBitValue(6, settings.sdmSettings.sdmEnabled) + settings.commMode.getModeNumber();
		  data.add((byte)fileOption);
  
		  int perm1 = settings.readPerm * Util.lsbBitValue(4) + settings.writePerm;
		  int perm2 = settings.readWritePerm * Util.lsbBitValue(4) + settings.changePerm;
		  data.add((byte)perm2);
		  data.add((byte)perm1);
  
		  if(settings.sdmSettings.sdmEnabled) {
			int sdmOptions = Util.unsignedByteToInt(Util.lsbBitValue(7, settings.sdmSettings.sdmOptionUid)) |
				Util.unsignedByteToInt(Util.lsbBitValue(6, settings.sdmSettings.sdmOptionReadCounter)) |
				Util.unsignedByteToInt(Util.lsbBitValue(5, settings.sdmSettings.sdmOptionReadCounterLimit)) |
				Util.unsignedByteToInt(Util.lsbBitValue(4, settings.sdmSettings.sdmOptionEncryptFileData)) |
				Util.unsignedByteToInt(Util.lsbBitValue(0, settings.sdmSettings.sdmOptionUseAscii));
			  data.add((byte)sdmOptions);
  
			  int sdmRights2 = 0xf0 | (settings.sdmSettings.sdmOptionReadCounter ? settings.sdmSettings.sdmReadCounterRetrievalPerm : 0xf);
			  data.add((byte)sdmRights2);
			  int sdmRights1 = settings.sdmSettings.sdmMetaReadPerm * Util.lsbBitValue(4) + settings.sdmSettings.sdmFileReadPerm;
			  data.add((byte)sdmRights1);
  
			  if(settings.sdmSettings.sdmMetaReadPerm == 0xe) {
				  if(settings.sdmSettings.sdmOptionUid) {
					  data.add(Util.getByte(settings.sdmSettings.sdmUidOffset, 0));
					  data.add(Util.getByte(settings.sdmSettings.sdmUidOffset, 1));
					  data.add(Util.getByte(settings.sdmSettings.sdmUidOffset, 2));
				  }
  
				  if(settings.sdmSettings.sdmOptionReadCounter) {
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterOffset, 0));
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterOffset, 1));
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterOffset, 2));
				  }
			  }
  
			  if(settings.sdmSettings.sdmMetaReadPerm >= 0 && settings.sdmSettings.sdmMetaReadPerm <= 4) {
				  data.add(Util.getByte(settings.sdmSettings.sdmPiccDataOffset, 0));
				  data.add(Util.getByte(settings.sdmSettings.sdmPiccDataOffset, 1));
				  data.add(Util.getByte(settings.sdmSettings.sdmPiccDataOffset, 2));
			  }
  
			  if(settings.sdmSettings.sdmFileReadPerm != 0xf) {
				  data.add(Util.getByte(settings.sdmSettings.sdmMacInputOffset, 0));
				  data.add(Util.getByte(settings.sdmSettings.sdmMacInputOffset, 1));
				  data.add(Util.getByte(settings.sdmSettings.sdmMacInputOffset, 2));
  
				  if(settings.sdmSettings.sdmOptionEncryptFileData) {
					  data.add(Util.getByte(settings.sdmSettings.sdmEncOffset, 0));
					  data.add(Util.getByte(settings.sdmSettings.sdmEncOffset, 1));
					  data.add(Util.getByte(settings.sdmSettings.sdmEncOffset, 2));
  
					  data.add(Util.getByte(settings.sdmSettings.sdmEncLength, 0));
					  data.add(Util.getByte(settings.sdmSettings.sdmEncLength, 1));
					  data.add(Util.getByte(settings.sdmSettings.sdmEncLength, 2));
				  }
  
				  data.add(Util.getByte(settings.sdmSettings.sdmMacOffset, 0));
				  data.add(Util.getByte(settings.sdmSettings.sdmMacOffset, 1));
				  data.add(Util.getByte(settings.sdmSettings.sdmMacOffset, 2));
  
				  if(settings.sdmSettings.sdmOptionReadCounterLimit) {
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterLimit, 0));
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterLimit, 1));
					  data.add(Util.getByte(settings.sdmSettings.sdmReadCounterLimit, 2));
				  }
			  }
		  }
		  
		  byte[] dataArray = new byte[data.size()];
		  int idx = 0;
		  for(byte b: data) {
			dataArray[idx] = b;
			idx++;
		  }
		  return dataArray;
	}
}