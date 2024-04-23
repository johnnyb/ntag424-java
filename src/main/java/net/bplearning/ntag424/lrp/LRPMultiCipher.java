package net.bplearning.ntag424.lrp;

import net.bplearning.ntag424.util.Crypto;

/**
 * An LRP (leakage-resistance primitive) MultiCipher based on 
 * NXP's document AN12304.  First, generate a
 * MultiCipher, which then contains individual
 * ciphers for different uses.
 *
 * Note that one parameter for LRP is "m", which is both
 * (a) the size of pieces (in bits) that the counter is
 * broken into, and (b) the number of plaintexts (2^m)
 * that is generated.  However, this implementation just
 * uses the parameter m = 4, both because that is
 * what NXP uses, and it simplifies the implementation,
 * since m = 4 is a half-byte.  Theoretically, though,
 * I think you can have m be whatever size you want in
 * theory (though it needs to be 4 to work with the LRP
 * algorithm in the NXP chip).
 */
public class LRPMultiCipher {
	byte[] key;
	byte[][] plaintexts = new byte[16][];

    public static final byte[] UPPER = new byte[] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	public static final byte[] LOWER = new byte[]  { (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa };


    /**
     * Generates a new MuliCipher based on the given key.
     * @param key
     */
	public LRPMultiCipher(byte[] key) {
		this.key = key;
		
		// Algorithm 1 (pg. 5)
        byte[] h = Crypto.simpleAesEncrypt(
            key,
            UPPER
        );

		for(int i = 0; i < 16; i++) {
			plaintexts[i] = Crypto.simpleAesEncrypt(
                h,
                LOWER
            );
            h = Crypto.simpleAesEncrypt(
                h,
                UPPER
            );
		}
	}

	/**
	 * Generates a new cipher for the specific usage.
	 * @param idx
	 * @return
	 */
	public LRPCipher generateCipher(int idx) {
		// Algorithm 2 (pg. 5)
        byte[] h = Crypto.simpleAesEncrypt(
            key,
            LOWER
        );

        for(int i = 0; i < idx; i++) {
            h = Crypto.simpleAesEncrypt(
                h,
                UPPER
            );
        }
        byte[] newkey = Crypto.simpleAesEncrypt(
            h,
            LOWER
        );

        return new LRPCipher(this, newkey);
	}

    public byte[] getPlaintext(int idx) {
        return plaintexts[idx];
    }
}
