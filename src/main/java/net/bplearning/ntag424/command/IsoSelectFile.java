package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.util.ByteUtil;

public class IsoSelectFile implements Command {
	public static final byte SELECT_MODE_BY_FILE_IDENTIFIER = 0x00;
	public static final byte SELECT_MODE_CHILD_DF = 0x01;
	public static final byte SELECT_MODE_CHILD_EF = 0x02;
	public static final byte SELECT_MODE_PARENT_DF = 0x03;
	public static final byte SELECT_MODE_NAME = 0x04;

	public static void run(DnaCommunicator communicator, byte mode, int identifier) throws IOException {
		run(communicator, mode, new byte[]{ByteUtil.getByteLSB(identifier, 1), ByteUtil.getByteLSB(identifier, 0)});
	}
	
	public static void run(DnaCommunicator communicator, byte mode, byte[] identificationData) throws IOException {
		byte[] command = ByteUtil.combineByteArrays(
			new byte[] {
				0x00, // class
				(byte)0xa4, // ISOSelectFile
				mode, // select by file identifier (1, 2, 3, and 4 have various meanings as well)
				0x0c, // Don't return FCI
				(byte)identificationData.length
			}, 
			identificationData, 
			new byte[]{0x00} // Length of expected response
		);
		communicator.transceive(command);
	}
}
