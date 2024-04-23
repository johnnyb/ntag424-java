package net.bplearning.ntag424.card;

import java.io.IOException;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.constants.Permissions;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.sdm.PiccData;
import net.bplearning.ntag424.util.ByteUtil;

/**
 * This class manages a full keyset for your application.
 * Any key not explicitly set is set to the FACTORY_KEY.
 */
public class KeySet {
	protected KeyInfo[] keys = new KeyInfo[] {
		new KeyInfo(),
		new KeyInfo(),
		new KeyInfo(), 
		new KeyInfo(),
		new KeyInfo()
	};
	protected boolean usesLrp = false;
	protected int metaKey = Permissions.ACCESS_KEY2;
	protected int macFileKey = Permissions.ACCESS_KEY3;

	/**
	 * This is a helper function to synchronize all of the
	 * keys on a card to their current version.  Should be performed
	 * when logged out.  User should relogin after this completes.
	 * Assumes that key version 0 is the factory key.
	 * Also, current implementation can't sync if key0 is a diversified key.
	 */
	public boolean synchronizeKeys(DnaCommunicator comm) throws IOException {
		boolean wasSuccessful = true;
		int appKeyVersion = GetKeyVersion.run(comm, Permissions.ACCESS_KEY0);
		KeyInfo existingAppKeyInfo = keys[0].getKeyInfoForVersion(appKeyVersion);
		if(existingAppKeyInfo == null) {
			// Don't know this app key
			return false;
		}

		if(existingAppKeyInfo.diversifyKeys) {
			// Can't sync if the app key is diversified.  This is theoretically possible but only if RandomId is not active.
			return false;
		}

		if(usesLrp) {
			if(!LRPEncryptionMode.authenticateLRP(comm, Permissions.ACCESS_KEY0, existingAppKeyInfo.key)) {
				return false;
			}
		} else {
			if(!AESEncryptionMode.authenticateEV2(comm, Permissions.ACCESS_KEY0, existingAppKeyInfo.key)) {
				return false;
			}
		}

		// Have to count down because we will have to relogin after changing key 0.
		for(int i = Permissions.ACCESS_KEY4; i >= Permissions.ACCESS_KEY0; i--) {
			if(!keys[i].synchronizeKey(comm, i)) {
				wasSuccessful = false;
			}
		}
		return wasSuccessful;
	}

	/**
	 * Helper function to decode plain PICC data that is encoded as individual strings.
	 */
	public PiccData decodePiccData(String uidString, String readCounterString) {
		PiccData piccData = new PiccData(ByteUtil.hexToByte(uidString), (int) ByteUtil.msbBytesToLong(ByteUtil.hexToByte(readCounterString)), usesLrp);
		setMacFileKeyFor(piccData);
		return piccData;
	}

	/**
	 * Combines decoding and verifying into one step for the most common case.
	 * Returns null if the verification did not work correctly.
	 */
	public PiccData decodeAndVerifyPiccData(String uidString, String readCounterString, String macString) {
		PiccData piccData = keys[macFileKey].decodeAndVerifyMac(uidString, readCounterString, macString, usesLrp);
		setMacFileKeyFor(piccData);
		return piccData;
	}

	/**
	 * Decrypts the given encrypted (as a hex string) PICC data.
	 * If the access rights for the PICC are set to ACCESS_EVERYONE,
	 * then it simply decodes the PICC data as unencrypted bytes.
	 */
	public PiccData decryptPiccData(String encryptedPiccData) {
		PiccData piccData;
		if(metaKey == Permissions.ACCESS_EVERYONE) {
			piccData = PiccData.decodeFromBytes(ByteUtil.hexToByte(encryptedPiccData), usesLrp);
		} else {
			piccData = PiccData.decodeFromEncryptedBytes(ByteUtil.hexToByte(encryptedPiccData), keys[metaKey].key, usesLrp);
		}
		setMacFileKeyFor(piccData);
		return piccData;
	}

	/**
	 * Convenience function for generating and setting the MAC
	 * file key.  Doesn't do anything if the macFileKey is
	 * set to a non-key value.  Doesn't do anything if piccData
	 * is null.
	 */
	public void setMacFileKeyFor(PiccData piccData) {
		if(piccData == null) { return; }
		if(macFileKey >= Permissions.ACCESS_KEY0 && macFileKey <= Permissions.ACCESS_KEY4) {
			piccData.setMacFileKey(keys[macFileKey].generateKeyForCardUid(piccData.getUid()));
		}
	}

	// *** Getters and Setters *** //
	public void setKey(int keyNumber, KeyInfo keyInfo) { keys[keyNumber] = keyInfo; }
	public KeyInfo getKey(int keyNumber) { return keys[keyNumber]; }
	public boolean getUsesLrp() { return this.usesLrp; }
	public void setUsesLrp(boolean usesLrp) { this.usesLrp = usesLrp; }
	public int getMacFileKey(){ return this.macFileKey; }
	public void setMacFileKey(int macFileKey) { this.macFileKey = macFileKey; }
	public int getMetaKey(){ return metaKey; }
	public void setMetaKey(int metaKey) { this.metaKey = metaKey; }
}
