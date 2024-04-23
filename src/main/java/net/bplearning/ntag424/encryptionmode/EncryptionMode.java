package net.bplearning.ntag424.encryptionmode;

import java.io.IOException;

import net.bplearning.ntag424.DnaCommunicator;

/**
 * Encryption modes are attached to the DnaCommunicator object and gives it methods
 * for encrypting, decrypting, MAC-ing messages, and restarting sessions.
 * Usually, the encrpytion mode itself has a static method which initiates
 * the encryption mode, and these functions are utilized by DnaCommunicator
 * to actually perform the details.
 */
public interface EncryptionMode {
	/** Encrypts the given data.  message is considered to be the full message to be encrypted.  Generates padding. */
	byte[] encryptData(byte[] message);
	/** Decrypts the given data.  message is considered to be the full message to be decrypted.  Assumes a padded message. */
	byte[] decryptData(byte[] message);
	/** Generates a 16-byte MAC for the message (NOTE - this is usually shortened using Crypto.shortenCMAC) */
	byte[] generateMac(byte[] message);
	/** Does a complete restart of the communication using the originally authenticated key/keynum */
	void restartSession(DnaCommunicator comm) throws IOException;
	/** Restarts session using nonFirst means */
	void restartSessionNonFirst(DnaCommunicator comm) throws IOException;
}
