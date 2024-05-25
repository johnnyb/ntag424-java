package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class GetKeyVersion implements Command {
	public static int run(DnaCommunicator communicator, int keyNum) throws IOException {
		CommandResult result = communicator.nxpMacCommand(
				(byte)0x64,
				new byte[] {(byte)keyNum},
				null
		);
		result.throwUnlessSuccessful();
		return result.data[0];
	}
}
