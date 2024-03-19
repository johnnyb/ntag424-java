package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;

public class ReadData implements Command {
	public byte[] run(DnaCommunicator communicator, int fileNum, int offset, int length) throws IOException {
		FileSettings settings = GetFileSettings.run(communicator, fileNum);
		return run(communicator, settings.commMode, fileNum, offset, length);
	}

	public byte[] run(DnaCommunicator communicator, CommunicationMode mode, int fileNum, int offset, int length) throws IOException {
			CommandResult result = communicator.nxpSwitchedCommand(
				mode,
				(byte)0xad,
				new byte[] {
					(byte) fileNum,
					Util.getByte(offset, 0),
					Util.getByte(offset, 1),
					Util.getByte(offset, 2),
					Util.getByte(length, 0),
					Util.getByte(length, 1),
					Util.getByte(length, 2)
				}, 
				null
			);
			result.throwUnlessSuccessful();
			return result.data;
	}
}
