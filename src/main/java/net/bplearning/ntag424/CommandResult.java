package net.bplearning.ntag424;

import java.io.IOException;

import net.bplearning.ntag424.exception.ProtocolException;
import net.bplearning.ntag424.util.ByteUtil;

public class CommandResult {
	public byte[] data;
	public byte status1;
	public byte status2;

	public CommandResult(byte[] data, byte status1, byte status2) {
		this.data = data;
		this.status1 = status1;
		this.status2 = status2;
	}

	public CommandResult(byte[] rawData) {
		data = new byte[rawData.length - 2];
		System.arraycopy(rawData, 0, data, 0, data.length);
		status1 = rawData[rawData.length - 2];
		status2 = rawData[rawData.length - 1];
	}

	public boolean isSuccessStatus() {
		return 
			(status1 == PLAIN_OK || status1 == MAC_OK) 
			&& (status2 == SUCCESS || status2 == ADDITIONAL_FRAME_EXPECTED);
	}

	public void throwUnlessSuccessful() throws IOException {
		if(!isSuccessStatus()) {
			throw new ProtocolException("Invalid status result: " + ByteUtil.byteToHex(new byte[]{status1, status2}));
		}
	}

	// pgs 44-45

	// Status1 codes
	public final static byte PLAIN_OK = (byte)0x90;
	public final static byte MAC_OK = (byte)0x91;

	// Status2 codes
	//   Sucess codes:
	public final static byte SUCCESS = 0x00;
	public final static byte ADDITIONAL_FRAME_EXPECTED = (byte)0xaf; // Not an error - Command was successful, but is expecting another one

	//   Failure codes:
	public final static byte ILLEGAL_COMMAND = 0x1e;
	public final static byte NO_SUCH_KEY = 0x40;
	public final static byte LENGTH_ERROR = 0x7e;
	public final static byte PERMISSION_DENIED = (byte)0x9d;
	public final static byte PARAMETER_ERROR = (byte)0x9e;
	public final static byte AUTHENTICATION_DELAY = (byte)0xad;
	public final static byte AUTHENTICATION_ERROR = (byte)0xae;
	public final static byte BOUNDARY_ERROR = (byte)0xbe;
	public final static byte COMMAND_ABORTED = (byte)0xca;
	public final static byte FILE_NOT_FOUND = (byte)0xf0;
}
