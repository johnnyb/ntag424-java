package net.bplearning.ntag424.constants;

import javax.crypto.spec.IvParameterSpec;

/** Cryptography-related constants */
public final class Crypto {
    /** The number of bytes in the CMAC **before** shortening */
    public static final int CMAC_SIZE = 16;
    // ** Crypto Constants **
    public static IvParameterSpec zeroIVPS = new IvParameterSpec(new byte[16]); // pg. 24
    public static byte[] zeroBlock = new byte[16];
    public static byte[] fullPaddingBlock = new byte[] { (byte)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    public static byte marker = (byte)0x80;
    public static boolean[] RB_128;
    public static boolean[] RB_64;

    static {
        RB_128 = new boolean[128];
        RB_128[120] = true;
        RB_128[125] = true;
        RB_128[126] = true;
        RB_128[127] = true;
    }

    static {
        RB_64 = new boolean[64];
        RB_64[59] = true;
        RB_64[60] = true;
        RB_64[62] = true;
        RB_64[63] = true;
    }
}
