package net.bplearning.ntag424.sdm;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.aes.AESCMAC;
import net.bplearning.ntag424.lrp.LRPCMAC;
import net.bplearning.ntag424.lrp.LRPCipher;
import net.bplearning.ntag424.lrp.LRPMultiCipher;

public class PiccData {
	public byte[] uid;
	public int readCounter;
	public boolean usesLrp;
	byte[] macFileKey;

	public PiccData(byte[] uid, int readCounter, boolean usesLrp) {
		this.uid = uid;
		this.readCounter = readCounter;
		this.usesLrp = usesLrp;
	}

	protected PiccData() { }

	public static PiccData decodeFromBytes(byte[] piccRecord, boolean usesLrp) {
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

		pdata.usesLrp = usesLrp;

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

		return decodeFromBytes(alldata, usesLrp);
	}

	public byte[] generateLRPSessionKey(byte[] macKey) {
		// Pg. 42
		LRPMultiCipher multiCipher = new LRPMultiCipher(macKey);
		LRPCipher cipher = multiCipher.generateCipher(0);
		byte[] sv = generateLRPSessionVector();
		return cipher.cmac(sv);
	}

	public byte[] generateAESSessionEncKey(byte[] macKey) {
		// pg. 41
		byte[] sv = generateAESEncSessionVector();
		return Util.simpleAesCmac(macKey, sv);
	}

	public byte[] generateAESSessionMacKey(byte[] macKey) {
		// pg. 41
		byte[] sv = generateAESMACSessionVector();
		return Util.simpleAesCmac(macKey, sv);
	}

	public byte[] generateAESMACSessionVector() {
		return generateSessionVector(new byte[] {
			0x3c,
			(byte)0xc3,
			0x00,
			0x01,
			0x00,
			(byte)0x80
		}, null);
	}

	public byte[] generateAESEncSessionVector() {
		return generateSessionVector(new byte[] {
			(byte)0xc3,
			0x3c,
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
		if(uid != null) {
			if(!Util.arraysEqual(uid, new byte[]{0,0,0,0,0,0,0})) {
				System.arraycopy(uid, 0, sv, svIdx, uid.length);
				svIdx += uid.length;
			}
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

	public CMAC generateLRPCMAC(byte[] key) {
		LRPMultiCipher multiCipher = new LRPMultiCipher(generateLRPSessionKey(key));
		LRPCipher cipher = multiCipher.generateCipher(0);
		return new LRPCMAC(cipher);
	}

	public CMAC generateAESCMAC(byte[] key) {
            try {
				SecretKeySpec keySpec = new SecretKeySpec(generateAESSessionMacKey(key), "AES");

				Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

				cipher.init(Cipher.ENCRYPT_MODE, keySpec, Constants.zeroIVPS);
				AESCMAC mac = new AESCMAC(cipher, keySpec);
				return mac;
			} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
				e.printStackTrace();
				return null;
			}
		}

	public byte[] performCMAC(byte[] message) {
		CMAC cmac = usesLrp ? generateLRPCMAC(macFileKey) : generateAESCMAC(macFileKey);
		byte[] result = cmac.perform(message, Constants.CMAC_SIZE);
		return result;
	}

	public byte[] performShortCMAC(byte[] message) {
		return Util.shortenCMAC(performCMAC(message));
	};

	public void setMacFileKey(byte[] key) {
		macFileKey = key;
	}

	public byte[] decryptFileData(byte[] encryptedData) {
		if(usesLrp) {
			// Counter transformation is defined on pg. 39
			byte[] counterBytes = new byte[] {
				Util.getByte(readCounter, 0),
				Util.getByte(readCounter, 1),
				Util.getByte(readCounter, 2),
				0, 0, 0
			};

			byte[] sessionKey = generateLRPSessionKey(macFileKey);
			return Util.simpleLrpDecrypt(sessionKey, 1, counterBytes, encryptedData);

		} else {
			byte[] sessionKey = generateAESSessionEncKey(macFileKey);
			return Util.simpleAesDecrypt(sessionKey, encryptedData);
		}
	}
}
