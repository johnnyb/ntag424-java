package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.util.ByteUtil;

public class SetFailedAuthCounterSettings {
	public static void run(DnaCommunicator communicator, boolean enableCounter, int failCounterLimit, int failCounterDecrement) throws IOException {
		CommandResult result = communicator.nxpEncryptedCommand(
			(byte)0x5c, // SetConfiguration
			new byte[] { 0x0a }, // SetFailedAuthCounterSettings
			new byte[] {
				(byte)(enableCounter ? 0x01 : 0x00),
				ByteUtil.getByteLSB(failCounterLimit, 0),
				ByteUtil.getByteLSB(failCounterLimit, 1),
				ByteUtil.getByteLSB(failCounterDecrement, 0),
				ByteUtil.getByteLSB(failCounterDecrement, 1)
			});
		result.throwUnlessSuccessful();
	}
}
