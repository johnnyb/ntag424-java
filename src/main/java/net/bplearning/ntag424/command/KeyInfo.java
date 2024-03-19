package net.bplearning.ntag424.command;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.CMAC;
import net.bplearning.ntag424.Constants;

public class KeyInfo {
	public byte[] key;
	public byte[] diversificationData;
	public List<KeyInfo> oldKeys;

	public byte[] generateKeyForCardUid(byte[] uidBytes) {
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
	        cipher.init(Cipher.ENCRYPT_MODE, skey, Constants.zeroIVPS);
			return new CMAC(cipher, skey).diversifyKey(diversificationData, uidBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedOperationException | InvalidAlgorithmParameterException | InvalidKeyException e) {
			// should not occur
			e.printStackTrace();
			return null;
		}
	}
}
