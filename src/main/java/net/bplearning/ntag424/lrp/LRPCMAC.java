package net.bplearning.ntag424.lrp;

import java.util.List;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;

public class LRPCMAC implements CMAC {
	LRPCipher cipher;
	boolean[] subkey1;
	boolean[] subkey2;

	public LRPCMAC(LRPCipher cipher) {
		this.cipher = cipher;
		subkey1 = generateSubkey1();
		subkey2 = generateSubkey2();
	}

	boolean[] generateSubkey1() {
		boolean[] l = Util.toBitArray(cipher.evalLRP(Util.bytesToNibbles(Constants.zeroBlock), true));
		boolean[] l_shift = Util.shiftLeft(l, 1);
		
		if(Util.msb(l, 1)[0] == false) {
			return l_shift;
		} else {
			return Util.xor(l_shift, Constants.RB_128);
		}
	}

	boolean[] generateSubkey2() {
		boolean[] k1_shift = Util.shiftLeft(subkey1, 1);
        if(Util.msb(subkey1, 1)[0] == false) {
            return k1_shift;
        } else {
            return Util.xor(k1_shift, Constants.RB_128);
        }
	}

	public byte[] perform(byte[] message, int lengthBytes) {
		int length = lengthBytes * 8;

        // Block out message into groups (Steps 2-3)
        int b = Constants.blockSize * 8;
        boolean[] messageBits = Util.toBitArray(message);
        int mlen = messageBits.length;
        List<boolean[]> m_list = Util.groupBlocks(messageBits, b);
        if(m_list.size() == 0) {
            m_list.add(new boolean[0]); 
        }

        boolean[] last_block = m_list.get(m_list.size() - 1);

        // Use subkeys to finish out last block (Step 4)
        if(last_block.length != b) {
            last_block = Util.xor(Util.padblock(last_block, b), subkey2);
        } else {
            last_block = Util.xor(last_block, subkey1);
        }
        m_list.set(m_list.size() - 1, last_block);

        // Perform the hashing (Steps 5-6)
        boolean[] c_curr = new boolean[b];
        for(boolean[] m_block: m_list) {
            c_curr = Util.toBitArray(cipher.evalLRP(Util.bytesToNibbles(Util.toByteArray(Util.xor(c_curr, m_block))),true));
        }

        // Step 7
        boolean[] t = Util.msb(c_curr, length);

        // Return as a byte array
        return Util.toByteArray(t);
	}
}
