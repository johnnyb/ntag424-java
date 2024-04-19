package net.bplearning.ntag424.util;

import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

public final class ByteUtil {
    /** RNG we are using.  This is public only so that, for testing purposes, it can be replaced. */
    public static Random random = new SecureRandom();

    /** Returns the given byte of the value, LSB-first. */
    public static byte getByteLSB(long value, int byteNumber) {
        while(byteNumber > 0) {
            value = value >> 8;
            byteNumber--;
        }
        return (byte) value;
    }

    /** Returns a new array that is a subarray of the given array from the offset and length. */
    public static byte[] subArrayOf(byte[] array, int offset, int length) {
        byte[] newArray = new byte[length];
        System.arraycopy(array, offset, newArray, 0, length);
        return newArray;
    }

    /** Returns whether or not two byte arrays are equal. */
    public static boolean arraysEqual(byte[] a1, byte[] a2) {
        if(a1 == null && a2 == null) {
            return true; // Both null, both the same
        }
        if(a1 == null || a2 == null) {
            return false; // One null, not the same
        }
        if(a1.length != a2.length) {
            return false; // Different lengths, not the same
        }

        // Do a byte-for-byte check
        for(int i = 0; i < a1.length; i++) {
            if(a1[i] != a2[i]) {
                return false;
            }
        }

        // No differences, they are the same
        return true;
    }

    /** Combines multiple byte arrays into a single byte array.  Skips any null values.  If all values are null (or no values sent at all) it returns an empty array. */
    public static byte[] combineByteArrays(byte[] ...arraysToCombine) {
        // Calculate necessary array size
        int size = 0;
        for(byte[] nextArray: arraysToCombine) {
            if(nextArray != null) {
                size += nextArray.length;
            }
        }

        // Copy each array
        byte[] newArray = new byte[size];
        int offset = 0;
        for(byte[] nextArray: arraysToCombine) {
            if(nextArray != null) {
                System.arraycopy(nextArray, 0, newArray, offset, nextArray.length);
                offset += nextArray.length;
            }
        }

        // Done
        return newArray;
    }

    /** Generates an array of random bytes */
    public static byte[] randomByteArray(int size) {
        byte[] results = new byte[size];
        random.nextBytes(results);
        return results;
    }

    /** Byte-rotates a byte array left by the given number of rotations. */
    public static byte[] rotateLeft(byte[] val, int rotations) {
        byte[] result = new byte[val.length];
        for(int i = 0; i < val.length; i++) {
            int newIdx = i < rotations ? (val.length - (rotations + i)) : (i - rotations);
            result[newIdx] = val[i];
        }
        return result;
    }

    /** Byte-rotates a byte array right by the given number of rotations. */
    public static byte[] rotateRight(byte[] val, int rotations) {
        byte[] result = new byte[val.length];
        for(int i = 0; i < val.length; i++) {
            int newIdx = i >= (val.length - rotations) ? (i - val.length + rotations) : (i + rotations);
            result[newIdx] = val[i];
        }
        return result;
    }

    /** Element-by-element XOR of two byte arrays.  Assumes they are the same length. */
    public static byte[] xor(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length];
        for(int i = 0; i < result.length; i++) {
            result[i] = (byte)(a1[i] ^ a2[i]);
        }
        return result;
    }

    /** Element-by-element XOR of two bit arrays.  Assumes they are the same length. */
    public static boolean[] xor(boolean[] a1, boolean[]a2) {
        boolean[] result = new boolean[a1.length];
        for(int i = 0; i < result.length; i++) {
            result[i] = a1[i] ^ a2[i];
        }
        return result;
    }

    /** Converts a byte array to a bit array */
    public static boolean[] toBitArray(byte[] ary) {
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

    public static String byteToHex(byte[] data) {
        if(data == null) { return null; }
        StringBuilder sb = new StringBuilder();
        for(byte b: data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
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

    public static int leftNibble(byte input) {
        return (input & 0xF0 ) >> 4;
    }

    public static int rightNibble(byte input) {
        return input & 0x0F;
    }

    public static int unsignedByteToInt(byte b) {
        return (((int)b)&0xff);
    }

    public static long msbBytesToLong(byte[] data) {
        long shifter = 0;
        long value = 0;
        for(int idx = data.length - 1; idx >= 0; idx--) {
            value |= ((long)unsignedByteToInt(data[idx])) << shifter;
            shifter += 8;
        }
        return value;
    }

    public static int lsbBytesToInt(byte[] data) {
        int multiplier = 1;
        int value = 0;
        for(byte b: data) {
            value += unsignedByteToInt(b) * multiplier;
            multiplier *= 256;
        }
        return value;
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

    /**
     * Finds the "search" byte array within the "original" byte array, removes it,
     * and returns the new array and the index at which it was found.
     * If the "search" byte array is not found, returns the original byte array and -1.
     */
    public static Pair<byte[], Integer> findAndReplaceBytes(byte[] original, byte[] search, byte[] replacement) {
        int offset = findOffsetOf(original, search);
        if(offset == -1) {
            return new Pair<>(original, -1);
        }
        byte[] part1 = subArrayOf(original, 0, offset);
        int idxAfterSearch = offset + search.length;
        byte[] part2 = subArrayOf(original, idxAfterSearch, original.length - idxAfterSearch);
        return new Pair<>(combineByteArrays(part1, replacement, part2), offset);
    }

    public static int findOffsetOf(byte[] original, byte[] search) {
        if(search.length == 0) {
            return 0; // Empty search always returns beginning
        }

        int searchIdx = 0;
        for(int originalIdx = 0; originalIdx < original.length; originalIdx++) {
            if(original[originalIdx] == search[searchIdx]) {
                // Matches next character in sequence
                searchIdx++;
                if(searchIdx == search.length) {
                    // Found!  Return original index
                    return originalIdx - (search.length - 1);
                }
            } else {
                // Doesn't match next character in sequence
                searchIdx = 0;
            }
        }
        return -1;
    }

    public static byte[] generateRepeatingBytes(byte val, int dataLength) {
        byte[] result = new byte[dataLength];
        for(int i = 0; i < dataLength; i++) {
            result[i] = val;
        }
        return result;
    }
}
