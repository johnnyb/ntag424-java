package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class GetFileSettings implements Command {
	public static FileSettings run(DnaCommunicator communicator, int fileNum) throws IOException {
		// Pg. 69
		CommandResult result = communicator.nxpMacCommand(
			(byte)0xf5,
			new byte[] { (byte) fileNum },
			null
		);
		result.throwUnlessSuccessful();
		return FileSettings.decodeFromData(result.data);
	}
}
