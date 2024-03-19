package net.bplearning.ntag424;

import java.security.SecureRandom;
import java.util.Random;
import java.util.zip.CRC32;

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
}
