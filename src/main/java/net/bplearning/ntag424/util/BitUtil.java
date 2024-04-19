package net.bplearning.ntag424.util;

public final class BitUtil {
    /** Shifts bits left */
    public static boolean[] shiftLeft(boolean[] ary, int shifts) {
        boolean[] newArray = new boolean[ary.length];
        System.arraycopy(ary, shifts, newArray, 0, ary.length - shifts);
        return newArray;
    }

    /** Shifts bits right */
    public static boolean[] shiftRight(boolean[] ary, int shifts) {
        boolean[] newArray = new boolean[ary.length];
        System.arraycopy(ary, 0, newArray, shifts, ary.length - shifts);
        return newArray;
    }

    /** Rotates bits right */
    public static boolean[] rotateRight(boolean[] ary, int shifts) {
        boolean[] newArray = shiftRight(ary, shifts);
        System.arraycopy(ary, ary.length - shifts, newArray, 0, shifts);
        return newArray;
    }

    /** Rotates bits left */
    public static boolean[] rotateLeft(boolean[] ary, int shifts) {
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

    /** Converts a bit array to a byte array. */
    public  static byte[] toByteArray(boolean[] ary) {
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

    public static byte lsbBitValue(int bitIdx) {
        return lsbBitValue(bitIdx, true);
    }

    public static byte lsbBitValue(int bitIdx, boolean isSet) {
        if(!isSet) {
            return 0;
        }

        return (byte)(1 << bitIdx);
    }

    public static boolean getBitLSB(byte b, int bit) {
        return (b & (1 << bit)) != 0;
    }
}
