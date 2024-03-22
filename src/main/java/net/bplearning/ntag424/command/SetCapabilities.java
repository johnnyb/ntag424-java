package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class SetCapabilities {
	public static void run(DnaCommunicator communicator, boolean permanentlyUseLRP) throws IOException {
			// Pg. 56
			CommandResult result = communicator.nxpEncryptedCommand(
				(byte)0x5c, // SetConfiguration
				new byte[] {0x05}, // SetCapabilities
				new byte[] {
					0x00, // RFU
					0x00,
					0x00,
					0x00,
					(byte)(permanentlyUseLRP ? 0x02 : 0x0),
					0x00, // RFU
					0x00,
					0x00,
					0x00, // User-configured PDCap2.5?
					0x00  // User-configured PDCap2.6?
				}
			);
			result.throwUnlessSuccessful();
	}
}
