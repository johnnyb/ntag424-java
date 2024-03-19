package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.CommunicationMode;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;

public class WriteData implements Command {
	public static void run(DnaCommunicator communicator, CommunicationMode mode, int fileNum, byte[] data, int offset) throws IOException {
		CommandResult result = communicator.nxpSwitchedCommand(
			mode,
			(byte)0x8d,
			new byte[] {
				(byte)fileNum,
				Util.getByte(offset, 0),
				Util.getByte(offset, 1),
				Util.getByte(offset, 2),
				Util.getByte(data.length, 0),
				Util.getByte(data.length, 1),
				Util.getByte(data.length, 2)
			},
			data
		);
		result.throwUnlessSuccessful();
    }

	public static void run(DnaCommunicator communicator, int fileNum, byte[] data, int offset) throws IOException {
		FileSettings settings = GetFileSettings.run(communicator, fileNum);
		WriteData.run(communicator, settings.commMode, fileNum, data, offset);
	}
}
