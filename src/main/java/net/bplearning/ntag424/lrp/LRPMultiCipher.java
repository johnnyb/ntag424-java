package net.bplearning.ntag424.lrp;

import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;

/**
 * An LRP (leakage-resistance primitive) MultiCipher based on 
 * NXP's document AN12304.  First, generate a
 * MultiCipher, which then contains individual
 * ciphers for different uses.
 */
public class LRPMultiCipher {
	byte[] key;
	byte[][] plaintexts = new byte[16][];

    /**
     * Generates a new MuliCipher based on the given key.
     * @param key
     */
	public LRPMultiCipher(byte[] key) {
		this.key = key;
		
		// Algorithm 1 (pg. 5)
        byte[] h = Util.simpleAesEncrypt(
            key,
            Constants.upper
        );

		for(int i = 0; i < 16; i++) {
			plaintexts[i] = Util.simpleAesEncrypt(
                h,
                Constants.lower
            );
            h = Util.simpleAesEncrypt(
                h,
                Constants.upper
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
        byte[] h = Util.simpleAesEncrypt(
            key,
            Constants.lower
        );

        for(int i = 0; i < idx; i++) {
            h = Util.simpleAesEncrypt(
                h,
                Constants.upper
            );
        }
        byte[] newkey = Util.simpleAesEncrypt(
            h,
            Constants.lower
        );

        return new LRPCipher(this, newkey);
	}

    public byte[] getPlaintext(int idx) {
        return plaintexts[idx];
    }
}
