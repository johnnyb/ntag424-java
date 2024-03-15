package net.bplearning.ntag424.command;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;

public class IsoSelectFile implements Command {
	public static final byte SELECT_MODE_ANY = 0x00;
	public static final byte SELECT_MODE_CHILD_DF = 0x01;
	public static final byte SELECT_MODE_CHILD_EF = 0x02;
	public static final byte SELECT_MODE_PARENT_DF = 0x03;
	public static final byte SELECT_MODE_NAME = 0x04;

	public static void run(DnaCommunicator communicator, byte mode, int fileid) {
		byte[] bytes = new byte[] {
			0x00, // class
			(byte)0xa4, // ISOSelectFile
			0x00, // select by file identifier (1, 2, 3, and 4 have various meanings as well)
			0x0c, // Don't return FCI
			0x02, // Length of file identifier
			Util.getByte(fileid, 1),  // File identifier
			Util.getByte(fileid, 0),
			0x00 // Length of expected response
		};
		communicator.transceive(bytes);
	}
}
