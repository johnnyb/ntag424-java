package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.util.ByteUtil;

public class GetCardUid implements Command {
	public static byte[] run(DnaCommunicator communicator) throws IOException {
		CommandResult result = communicator.nxpEncryptedCommand((byte)0x51, null, null);
		result.throwUnlessSuccessful();
		return ByteUtil.subArrayOf(result.data, 0, 7);
	}
}
