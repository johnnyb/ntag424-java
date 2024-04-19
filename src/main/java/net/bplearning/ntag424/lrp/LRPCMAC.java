package net.bplearning.ntag424.lrp;

import java.util.List;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.util.BitUtil;
import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

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
		boolean[] l = ByteUtil.toBitArray(cipher.evalLRP(ByteUtil.bytesToNibbles(net.bplearning.ntag424.constants.Crypto.zeroBlock), true));
		boolean[] l_shift = BitUtil.shiftLeft(l, 1);
		
		if(BitUtil.msb(l, 1)[0] == false) {
			return l_shift;
		} else {
			return ByteUtil.xor(l_shift, net.bplearning.ntag424.constants.Crypto.RB_128);
		}
	}

	boolean[] generateSubkey2() {
		boolean[] k1_shift = BitUtil.shiftLeft(subkey1, 1);
        if(BitUtil.msb(subkey1, 1)[0] == false) {
            return k1_shift;
        } else {
            return ByteUtil.xor(k1_shift, net.bplearning.ntag424.constants.Crypto.RB_128);
        }
	}

	public byte[] perform(byte[] message, int lengthBytes) {
		int length = lengthBytes * 8;
        if(message == null) { message = new byte[0]; }
        // Block out message into groups (Steps 2-3)
        int b = LRPCipher.BLOCKSIZE_BITS;
        boolean[] messageBits = ByteUtil.toBitArray(message);
        int mlen = messageBits.length;
        List<boolean[]> m_list = Crypto.groupBlocks(messageBits, b);
        if(m_list.size() == 0) {
            m_list.add(new boolean[0]); 
        }

        boolean[] last_block = m_list.get(m_list.size() - 1);

        // Use subkeys to finish out last block (Step 4)
        if(last_block.length != b) {
            last_block = ByteUtil.xor(Crypto.padblock(last_block, b), subkey2);
        } else {
            last_block = ByteUtil.xor(last_block, subkey1);
        }
        m_list.set(m_list.size() - 1, last_block);

        // Perform the hashing (Steps 5-6)
        boolean[] c_curr = new boolean[b];
        for(boolean[] m_block: m_list) {
            c_curr = ByteUtil.toBitArray(cipher.evalLRP(ByteUtil.bytesToNibbles(BitUtil.toByteArray(ByteUtil.xor(c_curr, m_block))),true));
        }

        // Step 7
        boolean[] t = BitUtil.msb(c_curr, length);

        // Return as a byte array
        return BitUtil.toByteArray(t);
	}
}
