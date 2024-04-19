package net.bplearning.ntag424.card;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.ChangeKey;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.exception.ProtocolException;
import net.bplearning.ntag424.sdm.PiccData;
import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

/**
 * This class contains basic information about a key
 * used on the keycard.  There are no getters/setters,
 * just set the values directly.
 */
public class KeyInfo {
	/** The non-diversified key */
	public byte[] key = Ntag424.FACTORY_KEY;

	/** Used for key diversification. You can probably leave this to the default. */
	public byte[] applicationId = Ntag424.DESFIRE_AID;
	
	/** Used for key diversification. You can set this to whatever you want. */
	public byte[] systemIdentifier = new byte[]{};

	/** Used for key diversification. The standard says not to change this. */
	public byte[] diversityConstant = new byte[] { 0x01 };

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

		// NOTE - we are not including the padblock because the CMAC function already does it
		byte[] diversificationData = ByteUtil.combineByteArrays(diversityConstant, uidBytes, applicationId, systemIdentifier);
		return Crypto.simpleAesCmac(key, diversificationData);
	}

	/** This is a utility function to go through each old 
	 * key and try to change it to the current key. 
	 * This assumes that the LRP status has not changed.
	 */
	public boolean synchronizeKey(DnaCommunicator comm, int keyNum) throws IOException {
		byte[] uid = GetCardUid.run(comm);
		System.out.println("Getting card uid");
		byte[] cardKey = generateKeyForCardUid(uid);

		if(keyNum == 0) {
			// Key 0 doesn't need an old key - just set the new key
			ChangeKey.run(comm, keyNum, null, cardKey, version);
			return true;
		}
		
		List<KeyInfo> keysToTry = new LinkedList<>(oldKeys);
		keysToTry.add(new KeyInfo()); // factory key
		keysToTry.add(this); // If the key is already set, just change it to itself

		boolean wasSuccessful = false;
		for(KeyInfo key: keysToTry) {
			byte[] oldCardKey = key.generateKeyForCardUid(uid);
			try {
				System.out.println("Syncing key: " + keyNum);
				System.out.println("Old: " + ByteUtil.byteToHex(oldCardKey));
				System.out.println("To:" + ByteUtil.byteToHex(cardKey));
				ChangeKey.run(comm, keyNum, oldCardKey, cardKey, version);
				wasSuccessful = true;
				break;
			} catch (ProtocolException e) {
				// Probably just an invalid old key
			}
		}

		return wasSuccessful;
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
}
