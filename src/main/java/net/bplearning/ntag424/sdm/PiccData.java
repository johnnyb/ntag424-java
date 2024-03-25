package net.bplearning.ntag424.sdm;

import javax.crypto.Cipher;

import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.lrp.LRPCipher;
import net.bplearning.ntag424.lrp.LRPMultiCipher;

public class PiccData {
	public byte[] uid;
	public long readCounter;

	public static PiccData decodeFromBytes(byte[] piccRecord) {
		PiccData pdata = new PiccData();

		byte tag = piccRecord[0];
		int curIdx = 1;
		if((tag & 0b10000000) == 0) {
			// No UID Mirroring
		} else {
			pdata.uid = new byte[7];
			System.arraycopy(piccRecord, 1, pdata.uid, 0, 7);
			curIdx += 7;
		}

		if((tag & 0b01000000) == 0) {
			// No tag counter
		} else {
			pdata.readCounter = Util.lsbBytesToInt(Util.subArrayOf(piccRecord, curIdx, 3));
		}

		return pdata;
	}

	/**
	 * NOTE - Uses a non-diversified key
	 * @param encryptedData
	 * @param key
	 * @param usesLrp
	 * @return
	 */
	public static PiccData decodeFromEncryptedBytes(byte[] encryptedData, byte[] key, boolean usesLrp) {
		byte[] alldata;
		if(usesLrp) {
			// LRP encodes the LRP counter in the first 8 bytes
			alldata = Util.simpleLrpDecrypt(
				key, 0, 
				Util.subArrayOf(encryptedData, 0, 8), 
				Util.subArrayOf(encryptedData, 8, 16)
			);
		} else {
			alldata = Util.simpleAesDecrypt(key, encryptedData);
		}

		return decodeFromBytes(alldata);
	}

	public byte[] generateLRPSessionMacKey(byte[] macKey) {
		LRPMultiCipher multiCipher = new LRPMultiCipher(macKey);
		LRPCipher cipher = multiCipher.generateCipher(0);
		byte[] sv = generateLRPSessionVector();
		return cipher.cmac(sv);
	}

	public byte[] generateAESSessionMacKey(byte[] macKey) {
		byte[] sv = generateAESSessionVector();
		return Util.simpleAesCmac(macKey, sv);
	}

	public byte[] generateAESSessionVector() {
		return generateSessionVector(new byte[] {
			0x3c,
			(byte)0xc3,
			0x00,
			0x01,
			0x00,
			(byte)0x80
		}, null);
	}

	public byte[] generateSessionVector(byte[] prefix, byte[] suffix) {				
		// pg. 42
		byte[] sv = new byte[16];
		System.arraycopy(prefix, 0, sv, 0, prefix.length);
		int svIdx = prefix.length;
		if(!Util.arraysEqual(uid, new byte[]{0,0,0,0,0,0,0})) {
			System.arraycopy(uid, 0, sv, svIdx, uid.length);
			svIdx += uid.length;
		}
		if(readCounter > 0) {
			byte[] readCounterBytes = new byte[] {
				Util.getByte(readCounter, 0),
				Util.getByte(readCounter, 1),
				Util.getByte(readCounter, 2)
			};
			System.arraycopy(readCounterBytes, 0, sv, svIdx, readCounterBytes.length);
			svIdx += readCounterBytes.length;
		}
		if(suffix != null) {
			System.arraycopy(suffix, 0, sv, sv.length - suffix.length, suffix.length);
		}
		return sv;
	}

	public byte[] generateLRPSessionVector() {
		return generateSessionVector(new byte[]{ 
			0x00, 
			0x01,
			0x00,
			(byte)0x80
		}, new byte[] {
			0x1e,
			(byte)0xe1
		});
	}
}
