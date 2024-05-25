package net.bplearning.ntag424.card;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.ChangeKey;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.constants.Permissions;
import net.bplearning.ntag424.exception.ProtocolException;
import net.bplearning.ntag424.sdm.PiccData;
import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

import static net.bplearning.ntag424.constants.Ntag424.FACTORY_KEY;

/**
 * This class contains basic information about a key
 * used on the keycard.  There are no getters/setters,
 * just set the values directly.
 */
public class KeyInfo {
	/** The non-diversified key */
	public byte[] key = FACTORY_KEY;

	/** Used for key diversification. You can probably leave this to the default. */
	public byte[] applicationId = Ntag424.DESFIRE_AID;
	
	/** Used for key diversification. You can set this to whatever you want. */
	public byte[] systemIdentifier = new byte[]{};

	/** A list of old keys that have been used.  Used for synchronizing to a new key set. */
	public List<KeyInfo> oldKeys = new LinkedList<>();

	/** Whether or not to diversify keys */
	public boolean diversifyKeys = false;

	/** The current key version */
	public int version = 0;

	/**
	 * Generates a "diversified" key for the given
	 * UID if the diversification flag is set.
	 * Otherwise, it just returns the bare key.
	 * Diversification algorithm is taken from NXP document AN10922.
	 * @param uidBytes
	 * @return
	 */
	public byte[] generateKeyForCardUid(byte[] uidBytes) {
		if(!diversifyKeys) {
			return key;
		}

		return Crypto.diversifyKey(key, ByteUtil.combineByteArrays(uidBytes, applicationId, systemIdentifier));
	}

	/** This is a utility function to go through each old 
	 * key and try to change it to the current key.
	 * This assumes that the LRP status has not changed.
	 * Must be logged in.
	 * Throws an exception if there is a problem changing keys.
	 */
	public boolean synchronizeKey(byte[] cardUid, DnaCommunicator comm, int keyNum) throws IOException {
		int existingVersion = GetKeyVersion.run(comm, keyNum);
		if(existingVersion == version) {
			// Already synchronized
			return true;
		}

		KeyInfo oldKeyInfo = getKeyInfoForVersion(existingVersion);
		if(oldKeyInfo == null) {
			// Don't know anything about this key
			return false;
		}

		if(cardUid == null) {
			cardUid = GetCardUid.run(comm);
		}

		byte[] cardKey = generateKeyForCardUid(cardUid);

		if(keyNum == Permissions.ACCESS_KEY0) {
			// Key 0 doesn't need an old key - just set the new key
			ChangeKey.run(comm, keyNum, null, cardKey, version);
		} else {
			byte[] oldCardKey = oldKeyInfo.generateKeyForCardUid(cardUid);
			ChangeKey.run(comm, keyNum, oldCardKey, cardKey, version);
		}

		return true;
	}

	public boolean synchronizeKey(DnaCommunicator comm, int keyNum) throws IOException {
		return synchronizeKey(null, comm, keyNum);
	}


	public PiccData decodeAndVerifyMac(String uidString, String readCounterString, String macString, boolean usesLrp) {
		PiccData piccData = new PiccData(ByteUtil.hexToByte(uidString), (int) ByteUtil.msbBytesToLong(ByteUtil.hexToByte(readCounterString)), usesLrp);
		piccData.setMacFileKey(generateKeyForCardUid(piccData.getUid()));
		byte[] expectedMac = piccData.performShortCMAC(null);
		byte[] actualMac = ByteUtil.hexToByte(macString);
		if(!ByteUtil.arraysEqual(expectedMac, actualMac)) {
			return null;
		}
		return piccData;
	}


	/** Given the key version, return the relevant key.  For version 0, returns the factory key. */
	public KeyInfo getKeyInfoForVersion(int searchVersion) {
		if(version == searchVersion) {
			return this;
		}
		for(KeyInfo key: oldKeys) {
			if(key.version == searchVersion) {
				return key;
			}
		}
		if(searchVersion == 0) {
			return getFactoryKeyInfo();
		}
		return null;
	}

	public static KeyInfo getFactoryKeyInfo() {
		KeyInfo info = new KeyInfo();
		info.version = 0;
		info.key = FACTORY_KEY;
		info.diversifyKeys = false;
		return info;
	}
}
