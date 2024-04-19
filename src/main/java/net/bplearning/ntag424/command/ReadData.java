package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.util.ByteUtil;

public class ReadData implements Command {
	public static byte[] run(DnaCommunicator communicator, int fileNum, int offset, int length) throws IOException {
		FileSettings settings = GetFileSettings.run(communicator, fileNum);
		return run(communicator, settings.commMode, fileNum, offset, length);
	}

	public static byte[] run(DnaCommunicator communicator, CommunicationMode mode, int fileNum, int offset, int length) throws IOException {
			CommandResult result = communicator.nxpSwitchedCommand(
				mode,
				(byte)0xad,
				new byte[] {
					(byte) fileNum,
					ByteUtil.getByteLSB(offset, 0),
					ByteUtil.getByteLSB(offset, 1),
					ByteUtil.getByteLSB(offset, 2),
					ByteUtil.getByteLSB(length, 0),
					ByteUtil.getByteLSB(length, 1),
					ByteUtil.getByteLSB(length, 2)
				}, 
				null
			);
			result.throwUnlessSuccessful();
			return result.data;
	}
}
