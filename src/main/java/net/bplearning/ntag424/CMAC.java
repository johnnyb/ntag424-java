package net.bplearning.ntag424;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

public class CMAC {
	final Cipher cipher;
    final SecretKeySpec key;
	boolean[] subkey1;
	boolean[] subkey2;

	public CMAC(Cipher cipher, SecretKeySpec key) {
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

	public static boolean[] RB_128; {
		RB_128 = new boolean[128];
		RB_128[120] = true;
		RB_128[125] = true;
		RB_128[126] = true;
		RB_128[127] = true;
	}

	public static boolean[] RB_64; {
		RB_64 = new boolean[64];
		RB_64[59] = true;
		RB_64[60] = true;
		RB_64[62] = true;
		RB_64[63] = true;
	}

	static final int BLOCKSIZE_BITS = 128;

    boolean[] generateSubkey1() throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.ENCRYPT_MODE, key, Constants.zeroIVPS); // Pg. 24

        boolean[] zeroBlockBits = new boolean[BLOCKSIZE_BITS];
        boolean[] l = Util.toBitArray(cipher.doFinal(Util.toByteArray(zeroBlockBits)));
        boolean[] l_shift = Util.shiftLeft(l, 1);

        if(Util.msb(l, 1)[0] == false) {
            return l_shift;
        } else {
            return Util.xor(l_shift, RB_128);
        }
    }

    boolean[] generateSubkey2() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, Constants.zeroIVPS); // Pg. 24

        boolean[] k1_shift = Util.shiftLeft(subkey1, 1);
        if(Util.msb(subkey1, 1)[0] == false) {
            return k1_shift;
        } else {
            return Util.xor(k1_shift, RB_128);
        }
    }

    List<boolean[]> groupBlocks(boolean[] data, int groupSize) {
        int fullGroups = data.length / groupSize;
		List<boolean[]> newData = new LinkedList<>();
		for(int grpIdx = 0; grpIdx < fullGroups; grpIdx++) {
			boolean[] group = new boolean[groupSize];
			for(int idx = 0; idx < groupSize; idx++) {
				group[idx] = data[grpIdx * groupSize + idx];
			}
			newData.add(group);
		}
        
        int remaining = data.length % groupSize;
        if(remaining > 0) {
            int startIdx = fullGroups * groupSize;
            boolean[] group = new boolean[remaining];
            for(int idx = 0; idx < remaining; idx++) {
                group[idx] = data[startIdx];
                startIdx += 1;
            }
            newData.add(group);
        }

        return newData;
    }

    boolean[] padblock(boolean[] ary, int length) {
        boolean[] paddedBlock = new boolean[length];
        for(int idx = 0; idx < paddedBlock.length; idx++) {
            if(idx < ary.length) {
                paddedBlock[idx] = ary[idx];
            } else {
                paddedBlock[idx] = idx == ary.length; // puts in a 1 for first digit padding, and 0 for the remaining
            }
        }
        return paddedBlock;
    }

    public byte[] perform(byte[] message, int lengthBytes) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, Constants.zeroIVPS); // Pg. 24

			int length = lengthBytes * 8;
			// Block out message into groups (Steps 2-3)
			boolean[] messageBits = Util.toBitArray(message);
			int mlen = messageBits.length;
			List<boolean[]> m_list = groupBlocks(messageBits, BLOCKSIZE_BITS);
			if(m_list.size() == 0) {
				m_list = new LinkedList<>();
				m_list.add(new boolean[0]);
			}

			boolean[] last_block = m_list.get(m_list.size() - 1);

			// Use subkeys to finish out last block (Step 4)
			if(last_block.length != BLOCKSIZE_BITS) {
				last_block = Util.xor(padblock(last_block, BLOCKSIZE_BITS), subkey2);
			} else {
				last_block = Util.xor(last_block, subkey1);
			}
			m_list.set(m_list.size() - 1, last_block);

			// Perform the hashing (Steps 5-6)
			boolean[] c_curr = new boolean[BLOCKSIZE_BITS];
			for(boolean[] m_block: m_list) {

					c_curr = Util.toBitArray(cipher.doFinal(Util.toByteArray(Util.xor(c_curr, m_block))));
				
			}

			// Step 7
			boolean[] t = Util.msb(c_curr, length);

			// Return as a byte array
			return Util.toByteArray(t);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			// Should not occur
			e.printStackTrace();
			return null;
		}
    }

    // NOTE - documentation not clear if this is supposed to be evens (zero-indexed) or evens (one-indexed)
    //      - AN12196 pg. 21 indicates that it is one-indexed evens
    public byte[] performEvensOnly(byte[] message, int lengthBytes) {
        byte[] result = perform(message, lengthBytes);
        byte[] evens = new byte[result.length / 2];
        for(int idx = 0; idx < evens.length; idx++) {
            evens[idx] = result[idx * 2 + 1];
        }
        return evens;
    }

    public byte[] diversifyKey(byte[] applicationInfo, byte[] identifier) {
		byte[] data = Util.combineByteArrays(new byte[]{0x01}, identifier, applicationInfo);
        return perform(data, 16);
    }
}
