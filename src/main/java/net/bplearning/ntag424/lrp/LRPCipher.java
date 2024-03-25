package net.bplearning.ntag424.lrp;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;

import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;

public class LRPCipher {
	LRPMultiCipher multiCipher;
	byte[] key;
	long counter = 0;
	Integer counterSize = 8; // NOTE - the standard says that the counter size is variable, but testing says that it expects it to be fixed at 8 nibbles long
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

        int mask = (1 << Constants.nibbleSize) - 1;
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
            y = Util.simpleAesEncrypt(y, p);
        }
        if(isFinal) {
            y = Util.simpleAesEncrypt(
                y,
                Constants.zeroBlock
            );
        }
        return y;
	}

	public byte[] cryptFullBlocks(byte[] src, int cryptMode) {
		// Algorithm 4 (pg. 7)

        if((src.length % Constants.blockSize) != 0) {
            throw new RuntimeException("Bad block size");
        }

        byte[] result = new byte[src.length];
        int numBlocks = src.length / Constants.blockSize;
        for(int i = 0; i < numBlocks; i++) {
            int blockStart = Constants.blockSize * i;
            int[] x = getCounterNibbles();
            byte[] y = evalLRP(x, true);
            byte[] block = Util.subArrayOf(src, blockStart, Constants.blockSize);
            byte[] resultBlock = 
				cryptMode == Cipher.ENCRYPT_MODE 
					? Util.simpleAesEncrypt(y, block) 
					: Util.simpleAesDecrypt(y, block);
			System.arraycopy(resultBlock, 0, result, blockStart, resultBlock.length);

            counter++;
        }

        return result;
	}

	public byte[] encrypt(byte[] src) {
		int fullBlocks = src.length / Constants.blockSize;
        byte[] newSrc = new byte[(fullBlocks + 1) * Constants.blockSize];
		System.arraycopy(src, 0, newSrc, 0, src.length);
        if((src.length % Constants.blockSize) == 0) {
			System.arraycopy(Constants.fullPaddingBlock, 0, newSrc, newSrc.length - Constants.blockSize, Constants.fullPaddingBlock.length);
        } else {
            newSrc[src.length] = (byte)0x80;
        }
        return cryptFullBlocks(newSrc, Cipher.ENCRYPT_MODE);
	}

	public byte[] decrypt(byte[] src) {
		byte[] result = cryptFullBlocks(src, Cipher.DECRYPT_MODE);
		int lastIdx = result.length - 1;
		while(result[lastIdx] != Constants.marker) {
			lastIdx--;
		}
		return Util.subArrayOf(result, 0, lastIdx);
	}

	public void setCounterSize(Integer sz) {
		counterSize = sz;
	}

	public byte[] cmac(byte[] message) {
		return mac.perform(message, 16);
	}

	public void setCounter(long counter) {
		this.counter = counter;
	}
}
