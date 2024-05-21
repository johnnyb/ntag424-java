package net.bplearning.ntag424.command;

import java.util.ArrayList;
import java.util.List;

import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.constants.Permissions;
import net.bplearning.ntag424.sdm.SDMSettings;
import net.bplearning.ntag424.util.BitUtil;
import net.bplearning.ntag424.util.ByteUtil;

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
		settings.sdmSettings.sdmEnabled = BitUtil.getBitLSB(options, 6);

		// Pg. 13
		if(BitUtil.getBitLSB(options, 1)) {
			if(BitUtil.getBitLSB(options, 0)) {
				settings.commMode = CommunicationMode.FULL;
			}
		} else {
			if(BitUtil.getBitLSB(options, 0)) {
				settings.commMode = CommunicationMode.MAC;
			}
		}

		// Access rights - pg. 11
		settings.readPerm = ByteUtil.leftNibble(data[3]);
		settings.writePerm = ByteUtil.rightNibble(data[3]);
		settings.readWritePerm = ByteUtil.leftNibble(data[2]);
		settings.changePerm = ByteUtil.rightNibble(data[2]);

		settings.fileSize = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, 4, 3));
		int currOffset = 7;

		if(settings.sdmSettings.sdmEnabled) {
			byte sdmOptions = data[currOffset];
			currOffset++;
			settings.sdmSettings.sdmOptionUid = BitUtil.getBitLSB(sdmOptions, 7);
			settings.sdmSettings.sdmOptionReadCounter = BitUtil.getBitLSB(sdmOptions, 6);
			settings.sdmSettings.sdmOptionReadCounterLimit = BitUtil.getBitLSB(sdmOptions, 5);
			settings.sdmSettings.sdmOptionEncryptFileData = BitUtil.getBitLSB(sdmOptions, 4);
			settings.sdmSettings.sdmOptionUseAscii = BitUtil.getBitLSB(sdmOptions, 0);

			byte sdmAccessRights1 = data[currOffset];
			currOffset++;
			byte sdmAccessRights2 = data[currOffset];
			currOffset++;
			settings.sdmSettings.sdmMetaReadPerm = ByteUtil.leftNibble(sdmAccessRights1);
			settings.sdmSettings.sdmFileReadPerm = ByteUtil.rightNibble(sdmAccessRights1);
			settings.sdmSettings.sdmReadCounterRetrievalPerm = ByteUtil.rightNibble(sdmAccessRights2);

			if(settings.sdmSettings.sdmMetaReadPerm == 0xe) {
				if (settings.sdmSettings.sdmOptionUid) {
					settings.sdmSettings.sdmUidOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
				if (settings.sdmSettings.sdmOptionReadCounter) {
					settings.sdmSettings.sdmReadCounterOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
			}

			if(settings.sdmSettings.sdmMetaReadPerm >= 0 && settings.sdmSettings.sdmMetaReadPerm <= 4) {
				settings.sdmSettings.sdmPiccDataOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmSettings.sdmFileReadPerm != 0x0f) {
				settings.sdmSettings.sdmMacInputOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
				currOffset += 3;

				if(settings.sdmSettings.sdmOptionEncryptFileData) {
					settings.sdmSettings.sdmEncOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
					currOffset += 3;

					settings.sdmSettings.sdmEncLength = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}

				settings.sdmSettings.sdmMacOffset = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmSettings.sdmOptionReadCounterLimit) {
				settings.sdmSettings.sdmReadCounterLimit = ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}
		}

		return settings;
	}

	public byte[] encodeToData() {
		  // Pg. 65
		  List<Byte> data = new ArrayList<>(20);

		  FileSettings settings = this; // I copied this from a different class, so this makes the copy/pasting a lot easier
  
		  int fileOption = BitUtil.lsbBitValue(6, settings.sdmSettings.sdmEnabled) + settings.commMode.getModeNumber();
		  data.add((byte)fileOption);
  
		  int perm1 = settings.readPerm * BitUtil.lsbBitValue(4) + settings.writePerm;
		  int perm2 = settings.readWritePerm * BitUtil.lsbBitValue(4) + settings.changePerm;
		  data.add((byte)perm2);
		  data.add((byte)perm1);
  
		  if(settings.sdmSettings.sdmEnabled) {
			int sdmOptions = ByteUtil.unsignedByteToInt(BitUtil.lsbBitValue(7, settings.sdmSettings.sdmOptionUid)) |
				ByteUtil.unsignedByteToInt(BitUtil.lsbBitValue(6, settings.sdmSettings.sdmOptionReadCounter)) |
				ByteUtil.unsignedByteToInt(BitUtil.lsbBitValue(5, settings.sdmSettings.sdmOptionReadCounterLimit)) |
				ByteUtil.unsignedByteToInt(BitUtil.lsbBitValue(4, settings.sdmSettings.sdmOptionEncryptFileData)) |
				ByteUtil.unsignedByteToInt(BitUtil.lsbBitValue(0, settings.sdmSettings.sdmOptionUseAscii));
			  data.add((byte)sdmOptions);
  
			  int sdmRights2 = 0xf0 | (settings.sdmSettings.sdmOptionReadCounter ? settings.sdmSettings.sdmReadCounterRetrievalPerm : 0xf);
			  data.add((byte)sdmRights2);
			  int sdmRights1 = settings.sdmSettings.sdmMetaReadPerm * BitUtil.lsbBitValue(4) + settings.sdmSettings.sdmFileReadPerm;
			  data.add((byte)sdmRights1);
  
			  if(settings.sdmSettings.sdmMetaReadPerm == Permissions.ACCESS_EVERYONE) {
				// If PICC data is read in plaintext, the UID and the ReadCounter are controlled separately
				  if(settings.sdmSettings.sdmOptionUid) {
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmUidOffset, 0));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmUidOffset, 1));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmUidOffset, 2));
				  }
  
				  if(settings.sdmSettings.sdmOptionReadCounter) {
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterOffset, 0));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterOffset, 1));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterOffset, 2));
				  }
			  } else if(settings.sdmSettings.sdmMetaReadPerm != Permissions.ACCESS_NONE) {
				// If PICC data is encrypted, its all in one spot together
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmPiccDataOffset, 0));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmPiccDataOffset, 1));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmPiccDataOffset, 2));
			  }
  
			  if(settings.sdmSettings.sdmFileReadPerm != Permissions.ACCESS_NONE) {
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacInputOffset, 0));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacInputOffset, 1));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacInputOffset, 2));
  
				  if(settings.sdmSettings.sdmOptionEncryptFileData) {
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncOffset, 0));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncOffset, 1));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncOffset, 2));
  
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncLength, 0));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncLength, 1));
					  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmEncLength, 2));
				  }
  
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacOffset, 0));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacOffset, 1));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmMacOffset, 2));
 			  }

			  if(settings.sdmSettings.sdmOptionReadCounterLimit) {
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterLimit, 0));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterLimit, 1));
				  data.add(ByteUtil.getByteLSB(settings.sdmSettings.sdmReadCounterLimit, 2));
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
