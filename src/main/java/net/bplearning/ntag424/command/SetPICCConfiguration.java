package net.bplearning.ntag424.command;

import java.io.IOError;
import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class SetPICCConfiguration {
	/**
	 * Setting enableRandomId to true will PERMANENTLY enable RandomID on this tag.
	 * @param communicator
	 * @param enableRandomId
	 */
	public static void run(DnaCommunicator communicator, boolean enableRandomId) throws IOException {
		// Pg. 56
		CommandResult result = communicator.nxpEncryptedCommand(
			(byte)0x5c, // SetConfiguration
			new byte[]{ 0x00 }, // Set PICC configuration
			new byte[] { (byte)(enableRandomId ? 0x02 : 0x00) }
		);
		result.throwUnlessSuccessful();
	}
}
