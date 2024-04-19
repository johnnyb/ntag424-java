package net.bplearning.ntag424.lrp;

import java.util.LinkedList;

import javax.crypto.Cipher;

import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

public class LRPCipher {
	public static final int BLOCKSIZE_BYTES = 16;
	public static final int BLOCKSIZE_BITS = BLOCKSIZE_BYTES * 8;
	public static final int NIBBLE_BITS = 4;

	LRPMultiCipher multiCipher;
	byte[] key;
	long counter = 0;
	Integer counterSize = 8; // This is the number of **nibbles** in the counter. NOTE - the standard says that the counter size is variable, but testing says that it expects it to be fixed at 8 nibbles long, except for some SDM operations, which then go back and forth between 12 and 16.
	LRPCMAC mac;

	public LRPCipher(LRPMultiCipher multiCipher, byte[] key) {
		this.multiCipher = multiCipher;
		this.key = key;
		mac = new LRPCMAC(this);
	}
	
	/**
	 * Retrieves the counter as LSB nibbles, but
	 * only as many as needed to represent the counter.
	 * @return
	 */
	int[] getCounterNibbles() {
		LinkedList<Integer> nibbles = new LinkedList<>();

        int mask = (1 << NIBBLE_BITS) - 1;
        long ctr = counter;

        while(true) {
			if(counterSize == null) { // No fixed counter size - stop when no bytes left
				if(ctr == 0) {
					break;
				}
			} else {
				if(nibbles.size() == counterSize) { // fixed counter size - stop when we reach the size
					break;
				}	
			}

			int low = (int)(ctr & mask);
			nibbles.add(0, low);
			ctr = ctr >> 4;
        }

		int[] nibblesAry = new int[nibbles.size()];
		for(int i = 0; i < nibblesAry.length; i++) {
			nibblesAry[i] = nibbles.get(i);
		}

		return nibblesAry;
	}

	byte[] evalLRP(int[] pieces, boolean isFinal) {
		// Algorithm 3 (pg. 6)
		byte[] y = key;
        for(int piece: pieces) {
            byte[] p = multiCipher.getPlaintext(piece);
            y = Crypto.simpleAesEncrypt(y, p);
        }
        if(isFinal) {
            y = Crypto.simpleAesEncrypt(
                y,
                net.bplearning.ntag424.constants.Crypto.zeroBlock
            );
        }
        return y;
	}

	/**
	 * Unpadded encryption/decryption of full 16-byte blocks.
	 * @param src the material to encrypt/decrypt
	 * @param cryptMode set to Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE depending on purpose
	 * @return
	 */
	public byte[] cryptFullBlocks(byte[] src, int cryptMode) {
		// Algorithm 4 (pg. 7)
        if((src.length % BLOCKSIZE_BYTES) != 0) {
            throw new RuntimeException("Bad block size");
        }

        byte[] result = new byte[src.length];
        int numBlocks = src.length / BLOCKSIZE_BYTES;
        for(int i = 0; i < numBlocks; i++) {
            int blockStart = BLOCKSIZE_BYTES * i;
            int[] x = getCounterNibbles();
            byte[] y = evalLRP(x, true);
            byte[] block = ByteUtil.subArrayOf(src, blockStart, BLOCKSIZE_BYTES);
            byte[] resultBlock = 
				cryptMode == Cipher.ENCRYPT_MODE 
					? Crypto.simpleAesEncrypt(y, block)
					: Crypto.simpleAesDecrypt(y, block);
			System.arraycopy(resultBlock, 0, result, blockStart, resultBlock.length);

            counter++;
        }

        return result;
	}

	/**
	 * Encrypts a source message.  Adds padding if needed to get a full block.
	 * @param src
	 * @return
	 */
	public byte[] encrypt(byte[] src) {
		int fullBlocks = src.length / BLOCKSIZE_BYTES;
        byte[] newSrc = new byte[(fullBlocks + 1) * BLOCKSIZE_BYTES];
		System.arraycopy(src, 0, newSrc, 0, src.length);
        if((src.length % BLOCKSIZE_BYTES) == 0) {
			System.arraycopy(net.bplearning.ntag424.constants.Crypto.fullPaddingBlock, 0, newSrc, newSrc.length - BLOCKSIZE_BYTES, net.bplearning.ntag424.constants.Crypto.fullPaddingBlock.length);
        } else {
            newSrc[src.length] = (byte) net.bplearning.ntag424.constants.Crypto.marker;
        }
        return cryptFullBlocks(newSrc, Cipher.ENCRYPT_MODE);
	}

	/**
	 * Decrypt the given encryption message.  This assumes a padded message.
	 * @param src
	 * @return
	 */
	public byte[] decrypt(byte[] src) {
		// Decrypt everything
		byte[] result = cryptFullBlocks(src, Cipher.DECRYPT_MODE);

		// Back up until you find the final marker
		int lastIdx = result.length - 1;
		while(result[lastIdx] != net.bplearning.ntag424.constants.Crypto.marker) {
			lastIdx--;
		}

		// Return everything before that
		return ByteUtil.subArrayOf(result, 0, lastIdx);
	}

	// 
	public void setCounterSize(Integer sz) {
		counterSize = sz;
	}

	public byte[] cmac(byte[] message) {
		return mac.perform(message, net.bplearning.ntag424.constants.Crypto.CMAC_SIZE);
	}

	public void setCounter(long counter) {
		this.counter = counter;
	}
}
