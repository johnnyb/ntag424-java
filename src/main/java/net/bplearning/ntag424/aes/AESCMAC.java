package net.bplearning.ntag424.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.util.BitUtil;
import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

public class AESCMAC implements CMAC {
	static final int BLOCKSIZE_BITS = 128;

	final Cipher cipher;
    final SecretKeySpec key;
	boolean[] subkey1;
	boolean[] subkey2;

	public AESCMAC(Cipher cipher, SecretKeySpec key) {
		this.cipher = cipher;
		this.key = key;
		try {
			subkey1 = generateSubkey1();
			subkey2 = generateSubkey2();
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			// Should not happen
			e.printStackTrace();
		}
	}

    boolean[] generateSubkey1() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, key, net.bplearning.ntag424.constants.Crypto.zeroIVPS); // Pg. 24

        boolean[] zeroBlockBits = new boolean[BLOCKSIZE_BITS];
        boolean[] l = ByteUtil.toBitArray(cipher.doFinal(BitUtil.toByteArray(zeroBlockBits)));
        boolean[] l_shift = BitUtil.shiftLeft(l, 1);

        if(BitUtil.msb(l, 1)[0] == false) {
            return l_shift;
        } else {
            return ByteUtil.xor(l_shift, net.bplearning.ntag424.constants.Crypto.RB_128);
        }
    }

    boolean[] generateSubkey2() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, net.bplearning.ntag424.constants.Crypto.zeroIVPS); // Pg. 24

        boolean[] k1_shift = BitUtil.shiftLeft(subkey1, 1);
        if(BitUtil.msb(subkey1, 1)[0] == false) {
            return k1_shift;
        } else {
            return ByteUtil.xor(k1_shift, net.bplearning.ntag424.constants.Crypto.RB_128);
        }
    }

    public byte[] perform(byte[] message, int lengthBytes) {
		if(message == null) { message = new byte[0]; }
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, net.bplearning.ntag424.constants.Crypto.zeroIVPS); // Pg. 24

			int length = lengthBytes * 8;
			// Block out message into groups (Steps 2-3)
			boolean[] messageBits = ByteUtil.toBitArray(message);
			int mlen = messageBits.length;
			List<boolean[]> m_list = Crypto.groupBlocks(messageBits, BLOCKSIZE_BITS);
			if(m_list.size() == 0) {
				m_list = new LinkedList<>();
				m_list.add(new boolean[0]);
			}

			boolean[] last_block = m_list.get(m_list.size() - 1);

			// Use subkeys to finish out last block (Step 4)
			if(last_block.length != BLOCKSIZE_BITS) {
				last_block = ByteUtil.xor(Crypto.padblock(last_block, BLOCKSIZE_BITS), subkey2);
			} else {
				last_block = ByteUtil.xor(last_block, subkey1);
			}
			m_list.set(m_list.size() - 1, last_block);

			// Perform the hashing (Steps 5-6)
			boolean[] c_curr = new boolean[BLOCKSIZE_BITS];
			for(boolean[] m_block: m_list) {

					c_curr = ByteUtil.toBitArray(cipher.doFinal(BitUtil.toByteArray(ByteUtil.xor(c_curr, m_block))));
				
			}

			// Step 7
			boolean[] t = BitUtil.msb(c_curr, length);

			// Return as a byte array
			return BitUtil.toByteArray(t);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			// Should not occur
			e.printStackTrace();
			return null;
		}
    }
}
