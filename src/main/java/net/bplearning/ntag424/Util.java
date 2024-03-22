package net.bplearning.ntag424;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.zip.CRC32;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public final class Util {
	public final static byte getByte(long value, int byteNumber) {
		while(byteNumber > 0) {
			value = value >> 8;
			byteNumber--;
		}
		return (byte) value;
	}

	public final static byte[] subArrayOf(byte[] array, int offset, int length) {
		byte[] newArray = new byte[length];
		System.arraycopy(array, offset, newArray, 0, length);
		return newArray;
	}

	public final static boolean arraysEqual(byte[] a1, byte[] a2) {
		if(a1 == null && a2 == null) {
			return true;
		}
		if(a1.length != a2.length) {
			return false;
		}
		for(int i = 0; i < a1.length; i++) {
			if(a1[i] != a2[i]) {
				return false;
			}
		}
		return true;
	}

	public final static byte[] combineByteArrays(byte[] ...arraysToCombine) {
		int size = 0;
		for(byte[] nextArray: arraysToCombine) {
			if(nextArray != null) {
				size += nextArray.length;
			}
		}

		byte[] newArray = new byte[size];
		int offset = 0;
		for(byte[] nextArray: arraysToCombine) {
			if(nextArray != null) {
				System.arraycopy(nextArray, 0, newArray, offset, nextArray.length);
				offset += nextArray.length;
			}
		}

		return newArray;
	}

	public static Random random = new SecureRandom();
	public static byte[] randomByteArray(int size) {
		byte[] results = new byte[size];
		random.nextBytes(results);
		return results;
	}

	public static byte[] rotateLeft(byte[] val, int rotations) {
		byte[] result = new byte[val.length];
		for(int i = 0; i < val.length; i++) {
			int newIdx = i < rotations ? (val.length - (rotations + i)) : (i - rotations);
			result[newIdx] = val[i];
		}
		return result;
	}

	public static byte[] rotateRight(byte[] val, int rotations) {
		byte[] result = new byte[val.length];
		for(int i = 0; i < val.length; i++) {
			int newIdx = i >= (val.length - rotations) ? (i - val.length + rotations) : (i + rotations);
			result[newIdx] = val[i];
		}
		return result;
	}

	public final static byte[] xor(byte[] a1, byte[] a2) {
		byte[] result = new byte[a1.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = (byte)(a1[i] ^ a2[i]);
		}
		return result;
	}

	public final static boolean[] xor(boolean[] a1, boolean[]a2) {
		boolean[] result = new boolean[a1.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = a1[i] ^ a2[i];
		}
		return result;
	}

	public final static byte[] toByteArray(boolean[] ary) {
		byte[] newAry = new byte[ary.length / 8];
		int bitOffset = 0;
		for(int idx = 0; idx < newAry.length; idx++) {
			int b = 0x00;
			for(int bitIdx = 0; bitIdx < 8; bitIdx++) {
				if(ary[bitOffset]) {
					b = b | (1 << (7 - bitIdx));
				}
				bitOffset++;
			}
			newAry[idx] = (byte)b;
		}
		return newAry;
	}

	public final static boolean[] toBitArray(byte[] ary) {
		boolean[] bits = new boolean[ary.length * 8];

		int bitOffset = 0;
		for(int idx = 0; idx < ary.length; idx++) {
			int b = ary[idx];
			int comparator = 0b10000000;
			for(int bitIdx = 0; bitIdx < 8; bitIdx++) {
				int result = b & comparator;
				bits[bitOffset] = result != 0;
				comparator = comparator >> 1;
				bitOffset++;
			}
		}
	
		return bits;
	}

	public final static boolean[] shiftLeft(boolean[] ary, int shifts) {
		boolean[] newArray = new boolean[ary.length];
		System.arraycopy(ary, shifts, newArray, 0, ary.length - shifts);
		return newArray;
	}

	public final static boolean[] shiftRight(boolean[] ary, int shifts) {
		boolean[] newArray = new boolean[ary.length];
		System.arraycopy(ary, 0, newArray, shifts, ary.length - shifts);
		return newArray;
	}

	public final static boolean[] rotateRight(boolean[] ary, int shifts) {
		boolean[] newArray = shiftRight(ary, shifts);
		System.arraycopy(ary, ary.length - shifts, newArray, 0, shifts);
		return newArray;
	}

	public final static boolean[] rotateLeft(boolean[] ary, int shifts) {
		boolean[] newArray = shiftLeft(ary, shifts);
		System.arraycopy(ary, 0, newArray, ary.length - shifts, shifts);
		return newArray;
	}

	public final static boolean[] msb(boolean[] ary, int bits) {
		boolean[] newAry = new boolean[bits];
		System.arraycopy(ary, 0, newAry, 0, bits);
		return newAry;
	}

	public final static boolean[] lsb(boolean[] ary, int bits) {
		boolean[] newAry = new boolean[bits];
		System.arraycopy(ary, ary.length - bits, newAry, 0, bits);
		return newAry;
	}

	public final static byte[] padMessageToBlocksize(byte[] message, int blocksize) {
		int remainder = message.length % blocksize;
		int complete_blocks = message.length / blocksize;
		if(remainder == 0) {
			return message;
		}
	
		byte[] result = new byte[(complete_blocks + 1)*blocksize];
		System.arraycopy(message, 0, result, 0, message.length);
		result[message.length] = (byte)0x80;
		return result;
	}

	public static String byteToHex(byte[] data) {
		if(data == null) { return null; }
		StringBuilder sb = new StringBuilder();
		for(byte b: data) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

	public static boolean getBitLSB(byte b, int bit) {
		return (b & (1 << bit)) != 0;
	}
	
	public static byte leftNibble(byte b) {
		return (byte)(b & 0xf);
	}

	public static byte rightNibble(byte b) {
		return (byte)(b >> 4);
	}

	public static int lsbBytesToInt(byte[] data) {
		int multiplier = 1;
		int value = 0;
		for(byte b: data) {
			value += b * multiplier;
			multiplier *= 256;
		}
		return value;
	} 

	public static byte lsbBitValue(int bitIdx) {
		return lsbBitValue(bitIdx, true);
	}

	public static byte lsbBitValue(int bitIdx, boolean isSet) {
		if(!isSet) {
			return 0;
		}

		return (byte)(1 << bitIdx);
	}

	public static byte[] jamCrc32(byte[] value) {
		CRC32 crc = new CRC32();
    	crc.update(value);
    long result = crc.getValue();
    byte[] basicCRC = new byte[] {
		Util.getByte(result, 0),
		Util.getByte(result, 1),
		Util.getByte(result, 2),
		Util.getByte(result, 3)
	};
    byte[] jamCRC = xor(
        basicCRC,
		new byte[] {
			(byte) 0xff,
			(byte) 0xff,
			(byte) 0xff,
			(byte) 0xff,
		}
    );
    return jamCRC;
	}


	public static byte[] simpleAesEncrypt(byte[] key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES"); 
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, Constants.zeroIVPS);
			return cipher.doFinal(data);
		} catch(NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			// Should not happen
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] simpleAesDecrypt(byte[] key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES"); 
			cipher.init(Cipher.DECRYPT_MODE, secretKey, Constants.zeroIVPS);
			return cipher.doFinal(data);	
		} catch(NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			// Should not happen
			e.printStackTrace();
			return null;
		}
	}

	// NOTE - documentation not clear if this is supposed to be evens (zero-indexed) or evens (one-indexed)
    //      - AN12196 pg. 21 indicates that it is one-indexed evens
	public static byte[] shortenCMAC(byte[] originalCMAC) {
		byte[] evens = new byte[originalCMAC.length / 2];
        for(int idx = 0; idx < evens.length; idx++) {
            evens[idx] = originalCMAC[idx * 2 + 1];
        }
        return evens;
	}

	public static byte[] diversifyKey(CMAC cmac, byte[] applicationInfo, byte[] identifier) {
		byte[] data = Util.combineByteArrays(new byte[]{0x01}, identifier, applicationInfo);
        return cmac.perform(data, 16);
	}

	/**
	 * Converts an array of bytes to an array of nibbles.
	 * The result is an int array simply for convenience,
	 * both in implementation and in usage of results.
	 * @param bytes
	 * @return
	 */
	public static int[] bytesToNibbles(byte[] bytes) {
		int[] results = new int[bytes.length*2];
		for(int i = 0; i < bytes.length; i++) {
			int bval = bytes[i];
			bval = bval & 0xff;
			int rightNibble = bval & 0xf;
			int leftNibble = bval >> 4;
			results[i * 2] = leftNibble;
			results[i * 2 + 1] = rightNibble;
		}
		return results;
	}

	public static List<boolean[]> groupBlocks(boolean[] data, int groupSize) {
        int fullGroups = data.length / groupSize;
		List<boolean[]> newData = new LinkedList<>();
		for(int grpIdx = 0; grpIdx < fullGroups; grpIdx++) {
			boolean[] group = new boolean[groupSize];
			for(int idx = 0; idx < groupSize; idx++) {
				group[idx] = data[grpIdx * groupSize + idx];
			}
			newData.add(group);
		}
        
        int remaining = data.length % groupSize;
        if(remaining > 0) {
            int startIdx = fullGroups * groupSize;
            boolean[] group = new boolean[remaining];
            for(int idx = 0; idx < remaining; idx++) {
                group[idx] = data[startIdx];
                startIdx += 1;
            }
            newData.add(group);
        }

        return newData;
    }


    public static boolean[] padblock(boolean[] ary, int length) {
        boolean[] paddedBlock = new boolean[length];
        for(int idx = 0; idx < paddedBlock.length; idx++) {
            if(idx < ary.length) {
                paddedBlock[idx] = ary[idx];
            } else {
                paddedBlock[idx] = idx == ary.length; // puts in a 1 for first digit padding, and 0 for the remaining
            }
        }
        return paddedBlock;
    }

	public static byte[] hexToByte(String val) {
		val = val.toLowerCase();
		List<Byte> bytes = new LinkedList<>();
		byte curByte = 0;
		boolean hasLeftNibble = false;
		for(int i = 0; i < val.length(); i++) {
			int c = val.charAt(i);
			int curNibble = 0;
			if(c >= 'a' && c <= 'f') {
				curNibble = (c - 'a') + 10;
			} else if (c >= '0' && c <= '9') {
				curNibble = (c - '0');
			} else {
				// Not a hex value
				continue;
			}

			if(hasLeftNibble) {
				curByte = (byte)(curByte | curNibble);
				bytes.add(curByte);
				hasLeftNibble = false;
				curByte = 0;
			} else {
				curByte = (byte)(curNibble << 4);
				hasLeftNibble = true;
			}
		}

		byte[] result = new byte[bytes.size()];
		for(int i = 0; i < result.length; i++) {
			result[i] = bytes.get(i);
		}
		return result;
	}
}
