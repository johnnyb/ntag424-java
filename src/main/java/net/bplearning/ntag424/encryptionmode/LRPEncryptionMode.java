package net.bplearning.ntag424.encryptionmode;

import java.io.IOException;

import javax.crypto.Cipher;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.lrp.LRPCipher;
import net.bplearning.ntag424.lrp.LRPMultiCipher;
import net.bplearning.ntag424.util.ByteUtil;

public class LRPEncryptionMode implements EncryptionMode {
	LRPMultiCipher sessionMultiCipher;
	LRPCipher sessionLrpMacCipher;
	LRPCipher sessionLrpEncryptionCipher;

	// Only needed for restarting session
	protected byte[] authenticationKey;
	protected int authenticationKeyNum;

	public LRPEncryptionMode(DnaCommunicator communicator, LRPMultiCipher initialMultiCipher, byte[] rndA, byte[] rndB) {
		byte[] sessionKey = generateLRPSessionKey(initialMultiCipher, rndA, rndB);
		sessionMultiCipher = new LRPMultiCipher(sessionKey);
		sessionLrpMacCipher = sessionMultiCipher.generateCipher(0);
		sessionLrpEncryptionCipher = sessionMultiCipher.generateCipher(1);
	}

	public LRPCipher getSessionLrpEncryptionCipher() {
		return sessionLrpEncryptionCipher;
	}

	@Override
	public byte[] encryptData(byte[] message) {
		return sessionLrpEncryptionCipher.encrypt(message);
	}

	@Override
	public byte[] decryptData(byte[] message) {
		return sessionLrpEncryptionCipher.decrypt(message);
	}

	@Override
	public byte[] generateMac(byte[] message) {
		return sessionLrpMacCipher.cmac(message);
	}

	@Override
	public void restartSession(DnaCommunicator comm) throws IOException {
		LRPEncryptionMode.authenticateLRP(comm, authenticationKeyNum, authenticationKey);
	}

	@Override
	public void restartSessionNonFirst(DnaCommunicator comm) throws IOException {
		// FIXME - implement authenticateLRPNonFirst
	}

	public static byte[] generateLRPSessionKey(LRPMultiCipher multiCipher, byte[] a, byte[] b) {
 // pg. 33 - indexes are reversed, so just subtracting to get the 
 // indexes from the standard

 byte[] sv = new byte[] {
	 0x00, 0x01, // fixed
	 0x00, (byte)0x80, // fixed
	 a[15-15], a[15-14],
	 (byte)(a[15-13] ^ b[15-15]),
	 (byte)(a[15-12] ^ b[15-14]),
	 (byte)(a[15-11] ^ b[15-13]),
	 (byte)(a[15-10] ^ b[15-12]),
	 (byte)(a[15-9] ^ b[15-11]),
	 (byte)(a[15-8] ^ b[15-10]),
	 b[15-9], b[15-8], b[15-7], b[15-6], b[15-5], b[15-4], b[15-3], b[15-2], b[15-1], b[15-0],
	 a[15-7], a[15-6], a[15-5], a[15-4], a[15-3], a[15-2], a[15-1], a[15-0],
	 (byte)0x96,
	 0x69
 };
 return multiCipher.generateCipher(0).cmac(sv);
	}
	
	public static boolean authenticateLRP(DnaCommunicator communicator, int keyNum, byte[] keyData) throws IOException {
		// STAGE 1 Authentication (pg. 51)
		CommandResult result = communicator.nxpNativeCommand(
		   (byte)0x71,
		   new byte[] {
			(byte)keyNum,
			0x01, // Length of capability vector
			0x02  // Use LRP encryption
		   },
		   null,
		   null
	   );
	   result.throwUnlessSuccessful();

	   if(result.data[0] != 0x01) {
		communicator.log("Bad initial byte: " + result.data[0]);
		   return false; // Bad data
	   }

	   byte[] rndB = ByteUtil.subArrayOf(result.data, 1, 16);
	   byte[] rndA = ByteUtil.randomByteArray(16);

	   LRPMultiCipher initialMultiCipher = new LRPMultiCipher(keyData);
	   LRPEncryptionMode lrpMode = new LRPEncryptionMode(communicator, initialMultiCipher, rndA, rndB);
	   lrpMode.authenticationKey = keyData;
	   lrpMode.authenticationKeyNum = keyNum;

	   // STAGE 2 Authentication (pg. 52)
	   byte[] rndMac = lrpMode.generateMac(ByteUtil.combineByteArrays(rndA, rndB));

	   CommandResult stage2Result = communicator.nxpNativeCommand(
		   (byte)0xaf,
		   ByteUtil.combineByteArrays(rndA, rndMac),
		   null,
		   null
	   );

	   if(!stage2Result.isSuccessStatus()) {
		return false;
	   }

	   byte[] encryptedData = ByteUtil.subArrayOf(stage2Result.data, 0, 16);
	   byte[] macData = ByteUtil.subArrayOf(stage2Result.data, 16, 16);

	   byte[] decryptedData = lrpMode.sessionLrpEncryptionCipher.cryptFullBlocks(encryptedData, Cipher.DECRYPT_MODE);

	   byte[] expectedMacData = lrpMode.generateMac(ByteUtil.combineByteArrays(rndB, rndA, encryptedData));
	   if(!ByteUtil.arraysEqual(macData, expectedMacData)) {
		   return false;
	   }

	   byte[] ti = ByteUtil.subArrayOf(decryptedData, 0, 4);
	   communicator.startEncryptedSession(lrpMode, keyNum, 0, ti);
	   return true;
   }
}
