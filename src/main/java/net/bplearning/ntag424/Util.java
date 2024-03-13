package net.bplearning.ntag424;

import java.security.SecureRandom;
import java.util.Random;

public final class Util {
	public final static byte getByte(int value, int byteNumber) {
		while(byteNumber > 0) {
			value = value >> 8;
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
}
