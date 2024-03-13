package net.bplearning.ntag424.encryptionmode;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

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
	protected byte[] rndA;
	protected byte[] rndB;
	public AESEncryptionMode(DnaCommunicator communicator, SecretKeySpec key, byte[] rndA, byte[] rndB) {
		this.communicator = communicator;
		this.key = key;
		this.rndA = rndA;
		this.rndB = rndB;
	}

	@Override
	public byte[] encryptData(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'encryptData'");
	}

	@Override
	public byte[] decryptData(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'decryptData'");
	}

	@Override
	public byte[] generateMac(byte[] message) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'generateMac'");
	}

	public static void startSession(DnaCommunicator communicator) {
		
	}


    public boolean authenticateEV2First(DnaCommunicator communicator, int keyNum, byte[] keyData) throws ProtocolException {
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

    public boolean authenticateEV2NonFirst(int keyNum) {
        // Does not affect command counter

        return false;
    }
}
