package net.bplearning.ntag424;

import net.bplearning.ntag424.constants.Crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Helper class for Cipher so we don't have to keep try/catching exceptions everywhere.
 */
public class AESCipher {
	final Cipher currentCipher;
	public AESCipher(int opmode, Key key, AlgorithmParameterSpec spec) {
		currentCipher = getCipher(opmode, key, spec);
	}

	public AESCipher(int opmode, Key key) {
		currentCipher = getCipher(opmode, key, Crypto.zeroIVPS);
	}

	public static Cipher getCipher(int opmode, Key key, AlgorithmParameterSpec spec) {
		try {
			Cipher tmpCipher = Cipher.getInstance("AES/CBC/NoPadding");
			tmpCipher.init(opmode, key, spec);
			return tmpCipher;
		} catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			// Should not occur
			e.printStackTrace();
			return null;
		}
	}

	public byte[] doFinal(byte[] input) {
		try {
			return currentCipher.doFinal(input);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// should not occur
			e.printStackTrace();
			return null;
		}
	}
}
