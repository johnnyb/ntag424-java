package net.bplearning.ntag424.command;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.aes.AESCMAC;

// Largely taken from NXP document AN10922.
public class KeyInfo {
	public byte[] key;
	public byte[] applicationId = Constants.DESFIRE_AID;
	public byte[] systemIdentifier = new byte[]{};
	public byte[] diversityConstant = new byte[] { 0x01 };
	public List<KeyInfo> oldKeys;
	public boolean diversifyKeys = true;

	public byte[] generateKeyForCardUid(byte[] uidBytes) {
		if(!diversifyKeys) {
			return key;
		}

		// NOTE - we are not including the padblock because the CMAC function already does it
		byte[] diversificationData = Util.combineByteArrays(diversityConstant, uidBytes, applicationId, systemIdentifier);
		return Util.simpleAesCmac(key, diversificationData);
	}
}
