package net.bplearning.ntag424.util;

import net.bplearning.ntag424.aes.AESCMAC;
import net.bplearning.ntag424.lrp.LRPCipher;
import net.bplearning.ntag424.lrp.LRPMultiCipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.CRC32;

public final class Crypto {
    public static byte[] padMessageToBlocksize(byte[] message, int blocksize) {
        int remainder = message.length % blocksize;
        int complete_blocks = message.length / blocksize;
        if(remainder == 0) {
            return message;
        }

        byte[] result = new byte[(complete_blocks + 1)*blocksize];
        System.arraycopy(message, 0, result, 0, message.length);
        result[message.length] = (byte)0x80;
        return result;
    }

    /** This is the CRC method used by the DNA tags */
    public static byte[] jamCrc32(byte[] value) {
        CRC32 crc = new CRC32();
        crc.update(value, 0, value.length);
        long result = crc.getValue();
        byte[] basicCRC = new byte[] {
                ByteUtil.getByteLSB(result, 0),
                ByteUtil.getByteLSB(result, 1),
                ByteUtil.getByteLSB(result, 2),
                ByteUtil.getByteLSB(result, 3)
        };
        byte[] jamCRC = ByteUtil.xor(
                basicCRC,
                new byte[] {
                        (byte) 0xff,
                        (byte) 0xff,
                        (byte) 0xff,
                        (byte) 0xff,
                }
        );
        return jamCRC;
    }

    public static byte[] simpleAesEncrypt(byte[] key, byte[] data) {
        return simpleAesEncrypt(key, data, net.bplearning.ntag424.constants.Crypto.zeroIVPS);
    }

    public static byte[] simpleAesEncrypt(byte[] key, byte[] data, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            return cipher.doFinal(data);
        } catch(NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            // Should not happen
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] simpleAesDecrypt(byte[] key, byte[] data) {
        return simpleAesDecrypt(key, data, net.bplearning.ntag424.constants.Crypto.zeroIVPS);
    }

    public static byte[] simpleAesDecrypt(byte[] key, byte[] data, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return cipher.doFinal(data);
        } catch(NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            // Should not happen
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] simpleAesCmac(byte[] key, byte[] message) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        return simpleAesCmac(keySpec, message);
    }

    public static byte[] simpleAesCmac(SecretKeySpec key, byte[] message) {
        try {
Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, net.bplearning.ntag424.constants.Crypto.zeroIVPS);
AESCMAC mac = new AESCMAC(cipher, key);
return mac.perform(message, net.bplearning.ntag424.constants.Crypto.CMAC_SIZE);
} catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
// Should not occur
e.printStackTrace();
return null;
}
    }

    public static byte[] simpleLrpDecrypt(byte[] key, int cipherNum, byte[] counterBytes, byte[] encryptedData) {
        return simpleLrpDecrypt(key, cipherNum, ByteUtil.msbBytesToLong(counterBytes), counterBytes.length * 2, encryptedData);
    }

    public static byte[] simpleLrpDecrypt(byte[] key, int cipherNum, long counter, Integer counterSize, byte[] encryptedData) {
        LRPMultiCipher lrp = new LRPMultiCipher(key);
        LRPCipher cipher = lrp.generateCipher(cipherNum);
        cipher.setCounter(counter);
        cipher.setCounterSize(counterSize); // Not sure about this
        return cipher.cryptFullBlocks(encryptedData, Cipher.DECRYPT_MODE);
}

    // NOTE - documentation not clear if this is supposed to be evens (zero-indexed) or evens (one-indexed)
//      - AN12196 pg. 21 indicates that it is one-indexed evens
    public static byte[] shortenCMAC(byte[] originalCMAC) {
        byte[] evens = new byte[originalCMAC.length / 2];
for(int idx = 0; idx < evens.length; idx++) {
evens[idx] = originalCMAC[idx * 2 + 1];
}
return evens;
    }

    public static List<boolean[]> groupBlocks(boolean[] data, int groupSize) {
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

    public static boolean[] padblock(boolean[] ary, int length) {
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

    public static int roundUpToMultiple(int value, int multiple) {
        // Make sure we are on even blocks
        int blocks = value / multiple;
        if(value % multiple != 0) {
            blocks++;
        }
        return blocks * multiple;
    }

    public static final byte[] DIVERSITY_CONSTANT_128 = { 0x01 };
    public static final byte[] DIVERSITY_CONSTANT_192_1 = { 0x11 };
    public static final byte[] DIVERSITY_CONSTANT_192_2 = { 0x12 };
    public static final byte[] DIVERSITY_CONSTANT_256_1 = { 0x41 };
    public static final byte[] DIVERSITY_CONSTANT_256_2 = { 0x42 };

    /** 
     * Diversifies keys according to the AES standards in AN10922 for 128, 196, and 256 bit keys.
     * A wrong-sized key will throw and IllegalArgumentException.
     * The diversificationData should *not* include the diversity constant, but should include everything else (uid, application id, and system identifier).
     */
    public static byte[] diversifyKey(byte[] masterKey, byte[] diversificationData) {
		// NOTE - we are not including the padblock because the CMAC function already does it

        switch(masterKey.length) {
            case 16:
                return Crypto.simpleAesCmac(masterKey, ByteUtil.combineByteArrays(DIVERSITY_CONSTANT_128, diversificationData));

            case 24:
                byte[] a = Crypto.simpleAesCmac(masterKey, ByteUtil.combineByteArrays(DIVERSITY_CONSTANT_192_1, diversificationData));
                byte[] b = Crypto.simpleAesCmac(masterKey, ByteUtil.combineByteArrays(DIVERSITY_CONSTANT_192_2, diversificationData));
                return ByteUtil.combineByteArrays(
                    ByteUtil.subArrayOf(a, 0, 8),
                    ByteUtil.xor(
                        ByteUtil.subArrayOf(a, 8, 8),
                        ByteUtil.subArrayOf(b, 0, 8)
                    ),
                    ByteUtil.subArrayOf(b, 8, 8)
                );
            case 32:
                return ByteUtil.combineByteArrays(
                    Crypto.simpleAesCmac(masterKey, ByteUtil.combineByteArrays(DIVERSITY_CONSTANT_256_1, diversificationData)),
                    Crypto.simpleAesCmac(masterKey, ByteUtil.combineByteArrays(DIVERSITY_CONSTANT_256_2, diversificationData))
                );

            default:
                throw new IllegalArgumentException("Key must be 16, 24, or 32 bytes long");
        }
    }
}
