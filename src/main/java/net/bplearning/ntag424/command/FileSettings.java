package net.bplearning.ntag424.command;

import java.util.ArrayList;
import java.util.List;

import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.Util;

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

	// SDM Options
	public boolean sdmEnabled = false;
    public boolean sdmOptionUid = false;
    public boolean sdmOptionReadCounter = false;
    public boolean sdmOptionReadCounterLimit = false;
    public boolean sdmOptionEncryptFileData = false;
    public boolean sdmOptionUseAscii = true;

	// SDM Permissions
    public int sdmMetaReadPerm = 0xe;
    public int sdmFileReadPerm = 0xe;
    public int sdmReadCounterRetrievalPerm = 0xe;
    
	// SDM Offsets
	public int sdmUidOffset = 0;
    public int  sdmReadCounterOffset = 0;
    public int  sdmPiccDataOffset = 0;
    public int  sdmMacInputOffset = 0;
    public int  sdmMacOffset = 0;
    public int  sdmEncOffset = 0;
    public int  sdmEncLength = 0;
    public int  sdmReadCounterLimit = 0;
	
	public static FileSettings decodeFromData(byte[] data) {
		FileSettings settings = new FileSettings();

		byte fileType = data[0];
		byte options = data[1];
		settings.sdmEnabled = Util.getBitLSB(options, 6);

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
		settings.readPerm = Util.leftNibble(data[2]);
		settings.writePerm = Util.rightNibble(data[2]);
		settings.readWritePerm = Util.leftNibble(data[3]);
		settings.changePerm = Util.rightNibble(data[3]);

		settings.fileSize = Util.lsbBytesToInt(Util.subArrayOf(data, 4, 3));
		int currOffset = 7;

		if(settings.sdmEnabled) {
			byte sdmOptions = data[currOffset];
			currOffset++;
			settings.sdmOptionUid = Util.getBitLSB(sdmOptions, 7);
			settings.sdmOptionReadCounter = Util.getBitLSB(sdmOptions, 6);
			settings.sdmOptionReadCounterLimit = Util.getBitLSB(sdmOptions, 5);
			settings.sdmOptionEncryptFileData = Util.getBitLSB(sdmOptions, 4);
			settings.sdmOptionUseAscii = Util.getBitLSB(sdmOptions, 0);

			byte sdmAccessRights1 = data[currOffset];
			currOffset++;
			byte sdmAccessRights2 = data[currOffset];
			currOffset++;
			settings.sdmMetaReadPerm = Util.leftNibble(sdmAccessRights1);
			settings.sdmFileReadPerm = Util.rightNibble(sdmAccessRights1);
			settings.sdmReadCounterRetrievalPerm = Util.rightNibble(sdmAccessRights2);

			if(settings.sdmMetaReadPerm == 0xe) {
				if (settings.sdmOptionUid) {
					settings.sdmUidOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
				if (settings.sdmOptionReadCounter) {
					settings.sdmReadCounterOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}
			}

			if(settings.sdmMetaReadPerm >= 0 && settings.sdmMetaReadPerm <= 4) {
				settings.sdmPiccDataOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmFileReadPerm != 0x0f) {
				settings.sdmMacInputOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;

				if(settings.sdmOptionEncryptFileData) {
					settings.sdmEncOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;

					settings.sdmEncLength = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
					currOffset += 3;
				}

				settings.sdmMacOffset = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}

			if(settings.sdmOptionReadCounterLimit) {
				settings.sdmReadCounterLimit = Util.lsbBytesToInt(Util.subArrayOf(data, currOffset, 3));
				currOffset += 3;
			}
		}

		return settings;
	}

	public byte[] encodeToData() {
		  // Pg. 65
		  List<Byte> data = new ArrayList<>(20);

		  FileSettings settings = this; // I copied this from a different class, so this makes the copy/pasting a lot easier
  
		  int fileOption = Util.lsbBitValue(6, settings.sdmEnabled) + settings.commMode.getModeNumber();
		  data.add((byte)fileOption);
  
		  int perm1 = settings.readPerm * Util.lsbBitValue(4) + settings.writePerm;
		  int perm2 = settings.readWritePerm * Util.lsbBitValue(4) + settings.changePerm;
		  data.add((byte)perm2);
		  data.add((byte)perm1);
  
		  if(settings.sdmEnabled) {
			int sdmOptions = Util.lsbBitValue(7, settings.sdmOptionUid) +
				Util.lsbBitValue(6, settings.sdmOptionReadCounter) +
				Util.lsbBitValue(5, settings.sdmOptionReadCounterLimit) +
				Util.lsbBitValue(4, settings.sdmOptionEncryptFileData) +
				Util.lsbBitValue(0, settings.sdmOptionUseAscii);
			  data.add((byte)sdmOptions);
  
			  int sdmRights2 = 0xf * Util.lsbBitValue(4) + (settings.sdmOptionReadCounter ? settings.sdmReadCounterRetrievalPerm : 0xf);
			  data.add((byte)sdmRights2);
			  int sdmRights1 = settings.sdmMetaReadPerm * Util.lsbBitValue(4) + settings.sdmFileReadPerm;
			  data.add((byte)sdmRights1);
  
			  if(settings.sdmMetaReadPerm == 0xe) {
				  if(settings.sdmOptionUid) {
					  data.add(Util.getByte(settings.sdmUidOffset, 0));
					  data.add(Util.getByte(settings.sdmUidOffset, 1));
					  data.add(Util.getByte(settings.sdmUidOffset, 2));
				  }
  
				  if(settings.sdmOptionReadCounter) {
					  data.add(Util.getByte(settings.sdmReadCounterOffset, 0));
					  data.add(Util.getByte(settings.sdmReadCounterOffset, 1));
					  data.add(Util.getByte(settings.sdmReadCounterOffset, 2));
				  }
			  }
  
			  if(settings.sdmMetaReadPerm >= 0 && settings.sdmMetaReadPerm <= 4) {
				  data.add(Util.getByte(settings.sdmPiccDataOffset, 0));
				  data.add(Util.getByte(settings.sdmPiccDataOffset, 1));
				  data.add(Util.getByte(settings.sdmPiccDataOffset, 2));
			  }
  
			  if(settings.sdmFileReadPerm != 0xf) {
				  data.add(Util.getByte(settings.sdmMacInputOffset, 0));
				  data.add(Util.getByte(settings.sdmMacInputOffset, 1));
				  data.add(Util.getByte(settings.sdmMacInputOffset, 2));
  
				  if(settings.sdmOptionEncryptFileData) {
					  data.add(Util.getByte(settings.sdmEncOffset, 0));
					  data.add(Util.getByte(settings.sdmEncOffset, 1));
					  data.add(Util.getByte(settings.sdmEncOffset, 2));
  
					  data.add(Util.getByte(settings.sdmEncLength, 0));
					  data.add(Util.getByte(settings.sdmEncLength, 1));
					  data.add(Util.getByte(settings.sdmEncLength, 2));
				  }
  
				  data.add(Util.getByte(settings.sdmMacOffset, 0));
				  data.add(Util.getByte(settings.sdmMacOffset, 1));
				  data.add(Util.getByte(settings.sdmMacOffset, 2));
  
				  if(settings.sdmOptionReadCounterLimit) {
					  data.add(Util.getByte(settings.sdmReadCounterLimit, 0));
					  data.add(Util.getByte(settings.sdmReadCounterLimit, 1));
					  data.add(Util.getByte(settings.sdmReadCounterLimit, 2));
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