package net.bplearning.ntag424.lrp;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;

public class LRPCipher {
	LRPMultiCipher multiCipher;
	byte[] key;
	int counter = 0;
	int counterSize = 8;
	LRPCMAC mac;

	public LRPCipher(LRPMultiCipher multiCipher, byte[] key) {
		this.multiCipher = multiCipher;
		this.key = key;
	}
	
	/**
	 * Retrieves the counter as LSB nibbles, but
	 * only as many as needed to represent the counter.
	 * @return
	 */
	int[] getCounterNibbles() {
		LinkedList<Integer> nibbles = new LinkedList<>();

        int mask = (1 << Constants.nibbleSize) - 1;
        int ctr = counter;

        while(true) {
			if(nibbles.size() == counterSize) {
				break;
			}

			int low = ctr & mask;
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

	byte[] cryptFullBlocks(byte[] src, boolean isEncrypting) {
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
				isEncrypting 
					? Util.simpleAesEncrypt(y, block) 
					: Util.simpleAesDecrypt(y, block);
			System.arraycopy(result, blockStart, resultBlock, 0, resultBlock.length);

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
        return cryptFullBlocks(newSrc, true);
	}

	public byte[] decrypt(byte[] src) {
		byte[] result = cryptFullBlocks(src, false);
		int lastIdx = result.length - 1;
		while(result[lastIdx] != Constants.marker) {
			lastIdx--;
		}
		return Util.subArrayOf(result, 0, lastIdx);
	}
}
