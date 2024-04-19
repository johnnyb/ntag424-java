package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.util.ByteUtil;

public class GetReadCounter {
	public static int run(DnaCommunicator communicator, int fileNum) throws IOException {
		CommandResult result = communicator.nxpEncryptedCommand(
            (byte)0xf6,
			new byte[] { (byte) fileNum },
			null
        );
		result.throwUnlessSuccessful();
		return ByteUtil.lsbBytesToInt(ByteUtil.subArrayOf(result.data, 0, 3));
	}
}
