package net.bplearning.ntag424.encryptionmode;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.exception.DelayException;
import net.bplearning.ntag424.exception.EncryptionException;
import net.bplearning.ntag424.exception.ProtocolException;

public class AESEncryptionMode implements EncryptionMode {
	protected DnaCommunicator communicator;
	protected SecretKeySpec key;
    protected SecretKeySpec sessionEncryptionKey;
    protected SecretKeySpec sessionMacKey;
	protected byte[] rndA;
	protected byte[] rndB;
	public AESEncryptionMode(DnaCommunicator communicator, SecretKeySpec key, byte[] rndA, byte[] rndB) {
		this.communicator = communicator;
		this.key = key;
		this.rndA = rndA;
		this.rndB = rndB;
        sessionEncryptionKey = generateAESSessionKey(new byte[]{(byte)0xa5, 0x5a});
        sessionMacKey = generateAESSessionKey(new byte[]{0x5a, (byte)0xa5});
	}

    static final int BLOCKSIZE_BYTES = 16;

	@Override
	public byte[] encryptData(byte[] message) {
        // pg. 24

        byte[] transactionIdentifier = communicator.getActiveTransactionIdentifier();
        int commandCounter = communicator.getCommandCounter();
        byte[] ivinput = new byte[] {
            (byte)0xa5,
            0x5a,
            transactionIdentifier[0],
            transactionIdentifier[1],
            transactionIdentifier[2],
            transactionIdentifier[3],
            Util.getByte(commandCounter, 0), 
            Util.getByte(commandCounter, 1),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionEncryptionKey, Constants.zeroIVPS);
            byte[] ivdata = cipher.doFinal(ivinput);

            cipher.init(Cipher.ENCRYPT_MODE, sessionEncryptionKey, new IvParameterSpec(ivdata));
            byte[] result = cipher.doFinal(Util.padMessageToBlocksize(message, BLOCKSIZE_BYTES));
            return result;
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // Should not occur
            e.printStackTrace();
            return null;
        }

    }

	@Override
	public byte[] decryptData(byte[] message) {
        byte[] transactionIdentifier = communicator.getActiveTransactionIdentifier();
        int commandCounter = communicator.getCommandCounter();
        byte[] ivinput = new byte[] {
            0x5a,
            (byte)0xa5,
            transactionIdentifier[0],
            transactionIdentifier[1],
            transactionIdentifier[2],
            transactionIdentifier[3],
            Util.getByte(commandCounter, 0), // LSB-first (pg. 23)
            Util.getByte(commandCounter, 1),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionEncryptionKey, Constants.zeroIVPS);
            byte[] ivdata = cipher.doFinal(ivinput);
            cipher.init(Cipher.DECRYPT_MODE, sessionEncryptionKey, new IvParameterSpec(ivdata));
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Should not occur
            e.printStackTrace();
            return null;
        }
	}

	@Override
	public byte[] generateMac(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionMacKey, Constants.zeroIVPS);
            CMAC mac = new CMAC(cipher, sessionMacKey);
            return mac.performEvensOnly(message, 16);
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // Should not occur
            e.printStackTrace();
            return null;
        }
	}

    public static boolean authenticateEV2(DnaCommunicator communicator, int keyNum, byte[] keyData) throws IOException, ProtocolException {
        // STAGE 1 Authentication (pg. 46)
        CommandResult e_k_b = communicator.nxpNativeCommand(
			(byte)0x71,
			new byte[] {
				(byte)keyNum,
				0x00 // Length of capability vector
                // 0x00, // Use EV2 Messaging? Required?
                // No other capabilities (future use, I think)
			},
			null,
            null
		);
            
        if(e_k_b.status1 != (byte)0x91) {
            return false;
        }
        if(e_k_b.status2 == (byte)0xad) {
			throw new DelayException();
        }
        if(e_k_b.status2 != (byte)0xaf) {
            return false;
        }
        if(e_k_b.data.length != 16) {
            return false;
        }

        // STAGE 2 Authentication
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key = new SecretKeySpec(keyData, "AES");
    
            cipher.init(Cipher.DECRYPT_MODE, key, Constants.zeroIVPS);
            byte[] b = cipher.doFinal(e_k_b.data);
            byte[] a = Util.randomByteArray(16);
    
            byte[] bprime = Util.rotateLeft(b, 1);
    
            cipher.init(Cipher.ENCRYPT_MODE, key, Constants.zeroIVPS);
            byte[] e_k_a_bp = cipher.doFinal(Util.combineByteArrays(a, bprime));
    
            CommandResult e_k_ti_ap_pdcap_pcdcap = communicator.nxpNativeCommand(
                (byte)0xaf,
                e_k_a_bp,
                null,
                null
            );
    
            if(e_k_ti_ap_pdcap_pcdcap.status1 != (byte)0x91) {
                return false;
            }
    
            if(e_k_ti_ap_pdcap_pcdcap.status2 != 0x00) {
                return false;
            }
    
            cipher.init(Cipher.DECRYPT_MODE, key, Constants.zeroIVPS);
            byte[] ti_ap_pdcap_pcdcap = cipher.doFinal(e_k_ti_ap_pdcap_pcdcap.data);
    
            byte[] ti = Util.subArrayOf(ti_ap_pdcap_pcdcap, 0, 4);
            byte[] aprime = Util.subArrayOf(ti_ap_pdcap_pcdcap, 4, 16);
    
            // NOTE - should save these
            byte[] pdcap = Util.subArrayOf(ti_ap_pdcap_pcdcap, 20, 6);
            byte[] pcdcap = Util.subArrayOf(ti_ap_pdcap_pcdcap, 26, 6);
    
            if(!Util.arraysEqual(Util.rotateRight(aprime, 1), a)) {
                return false;
            }
    
            AESEncryptionMode encryptionMode = new AESEncryptionMode(communicator, key, a, b);
            communicator.startEncryptedSession(encryptionMode, keyNum, 0, ti);
            return true;
        } catch(BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidParameterException e) {
            throw new EncryptionException(e.getMessage());
        }
    }

    public void restartSession() {
        // FIXME - run authenticateEV2NonFirst (pgs. 25 & 51)
    }

    protected byte[] generateAESSessionVector(byte[] purpose) {
        // pg. 27

        // NOTE - our indices are reversed from theirs,
        //        so doing 15 - x so you can see their indices
        return new byte[] {
            purpose[0], purpose[1],
            0x00, 0x01, // Counter (fixed)
            0x00, (byte)0x80, // Bits (128-bit key)
            rndA[15-15], rndA[15-14],
            (byte)(rndA[15-13] ^ rndB[15-15]),
            (byte)(rndA[15-12] ^ rndB[15-14]),
            (byte)(rndA[15-11] ^ rndB[15-13]),
            (byte)(rndA[15-10] ^ rndB[15-12]),
            (byte)(rndA[15-9] ^ rndB[15-11]),
            (byte)(rndA[15-8] ^ rndB[15-10]),
            rndB[15-9], rndB[15-8], rndB[15-7], rndB[15-6], rndB[15-5], rndB[15-4], rndB[15-3], rndB[15-2], rndB[15-1], rndB[15-0],
            rndA[15-7], rndA[15-6], rndA[15-5], rndA[15-4], rndA[15-3], rndA[15-2], rndA[15-1], rndA[15-0]
        };
    }

    protected SecretKeySpec generateAESSessionKey(byte[] purpose) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, Constants.zeroIVPS);
            byte[] sv = generateAESSessionVector(purpose);
            CMAC cmac = new CMAC(cipher, key);
            byte[] keyData = cmac.perform(sv, 16);
    
            return new SecretKeySpec(keyData, "AES");
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            // Shouldn't happen
            e.printStackTrace();
            return null;
        }
    }
}
