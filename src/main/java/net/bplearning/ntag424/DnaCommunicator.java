package net.bplearning.ntag424;

import java.io.IOException;
import java.util.function.Consumer;
import java.util.function.Function;

import net.bplearning.ntag424.command.IsoSelectFile;
import net.bplearning.ntag424.encryptionmode.EncryptionMode;
import net.bplearning.ntag424.exception.MACValidationException;
import net.bplearning.ntag424.exception.ProtocolException;

public class DnaCommunicator {
	public interface ThrowableFunction <T, R, E extends Throwable> {
		public R apply(T input) throws E;
	}

	protected ThrowableFunction<byte[], byte[], IOException> transceiver;
	protected EncryptionMode encryptionMode;
	protected byte[] activeTransactionIdentifier;
	protected int activeKeyNumber;
	protected int commandCounter;
	protected Consumer<String> logger = (val) -> {}; // Default to an empty logger

	public void log(String value) {
		logger.accept(value);
	}

	public void log(String tag, byte[] data) {
		log(tag + ": " + Util.byteToHex(data));
	}

	public void setLogger(Consumer<String> newLoggerFunction) {
		logger = newLoggerFunction;
	}

	public void setTransceiver(ThrowableFunction<byte[], byte[], IOException> newTransceiver) {
		transceiver = newTransceiver;
	}

	public byte[] transceive(byte[] bytesToSend) throws IOException{
		log("BytesSending", bytesToSend);
		byte[] results = transceiver.apply(bytesToSend);
		log("BytesReceived", results);
		return results;
	}

	public byte[] getActiveTransactionIdentifier() {
		return activeTransactionIdentifier;
	}

	public int getActiveKeyNumber() {
		return activeKeyNumber;
	}

	public int getCommandCounter() { return commandCounter; }

	/**
	 * Begin a session.  Call this immediately after creating, before authenticating.  I think this is undocumented, but required.
	 */
	public void beginCommunication() throws IOException {
		log("Beginning communication");
		IsoSelectFile.run(this, IsoSelectFile.SELECT_MODE_BY_FILE_IDENTIFIER, Constants.DF_FILE_ID);
	}

	// **** SESSION MANAGEMENT **** //

	/**
	 * This method is called by the session encryption functions
	 * to start the encrypted session.  Should not be called
	 * directly by application code.
	 * @param encryptionMode
	 * @param keyNumber
	 * @param commandCounter
	 * @param transactionIdentifier
	 */
	public void startEncryptedSession(EncryptionMode encryptionMode, int keyNumber, int commandCounter, byte[] transactionIdentifier) {
		this.encryptionMode = encryptionMode;
		this.activeKeyNumber = keyNumber;
		this.commandCounter = commandCounter;
		this.activeTransactionIdentifier = transactionIdentifier;
	}
	
	// **** BASIC COMMAND ARCHITECTURE **** //

	public static byte LENGTH_ALL = 0x00;

	/**
	 * Runs a standard ISO/IEC7816-4 communication frame
	 * @param instructionClass
	 * @param instruction
	 * @param param1
	 * @param param2
	 * @param data
	 * @param expectedResponseLength
	 * @return
	 * @throws IOException
	 */
	public CommandResult isoCommand(byte instructionClass, byte instruction, byte param1, byte param2, byte[] data, byte expectedResponseLength) throws IOException {
		byte[] command = Util.combineByteArrays(
			new byte[] {
				instructionClass,
				instruction,
				param1,
				param2,
				(byte)(data == null ? 0 : data.length)
			},
			data,
			new byte[] {
				expectedResponseLength
			}
		);

		byte[] results = transceive(command);

		return new CommandResult(results);
	}

	/**
	 * Runs a basic framed NXP native command.
	 * Does not affect the command counter.
	 */
	public CommandResult nxpNativeCommand(byte cmd, byte[] hdr, byte[] data, byte[] macData) throws IOException {
		return isoCommand((byte)0x90, cmd, (byte)0x00, (byte)0x00, Util.combineByteArrays(hdr, data, macData), LENGTH_ALL);
    }

	/**
	 * Runs a plain, unencrypted command.
	 * @param cmd
	 * @param hdr
	 * @param data
	 * @return
	 */
	public CommandResult nxpPlainCommand(byte cmd, byte[] hdr, byte[] data) throws IOException {
		commandCounter += 1;
		return nxpNativeCommand(cmd, hdr, data, null);
	}

	/**
	 * Runs a command which needs MAC authentication.
	 * @param cmd
	 * @param hdr
	 * @param data
	 * @return
	 * @throws ProtocolException
	 */
	public CommandResult nxpMacCommand(byte cmd, byte[] hdr, byte[] data) throws IOException, ProtocolException {
        // PREPARE MAC DATA
		byte[] cipherBase = new byte[] {
            cmd,
			Util.getByte(commandCounter, 0),
			Util.getByte(commandCounter, 1),
			activeTransactionIdentifier[0],
			activeTransactionIdentifier[1],
			activeTransactionIdentifier[2],
			activeTransactionIdentifier[3]
		};
		byte[] cipherData = Util.combineByteArrays(cipherBase, hdr, data);


        // PERFORM MAC WITH APPROPRIATE ALGORITHM
        byte[] macData = encryptionMode.generateMac(cipherData);

        // DO THE COMMAND
        CommandResult result = nxpNativeCommand(cmd, hdr, data, macData);
        commandCounter += 1;

        // IF NO MAC, JUST RETURN
        int sz = result.data.length;
        if(sz < 8) {
			return new CommandResult(new byte[0], result.status1, result.status2);
        }

        byte[] dataBytes = Util.subArrayOf(result.data, 0, sz - 8);
        byte[] macBytes = Util.subArrayOf(result.data, sz - 8, 8);

        // Validate MAC result
		byte[] resultMacInputHeader = new byte[] {
			result.status2,
			Util.getByte(commandCounter, 0),
			Util.getByte(commandCounter, 1),
			activeTransactionIdentifier[0],
			activeTransactionIdentifier[1],
			activeTransactionIdentifier[2],
			activeTransactionIdentifier[3]
		};
		byte[] resultMacInput = Util.combineByteArrays(resultMacInputHeader, dataBytes);
        byte[] resultMacData = encryptionMode.generateMac(resultMacInput);
        if(!Util.arraysEqual(resultMacData, macBytes)) {
			throw new MACValidationException();
        }

		return new CommandResult(dataBytes, result.status1, result.status2);
    }

	/**
	 * Runs a command which requires session encryption.
	 * @param cmd
	 * @param hdr
	 * @param data
	 * @return
	 * @throws ProtocolException
	 */
	public CommandResult nxpEncryptedCommand(byte cmd, byte[] hdr, byte[] data) throws IOException {
		byte[] encryptedData;
		if(data == null || data.length == 0) {
			encryptedData = data;
		} else {
			encryptedData = encryptionMode.encryptData(data);
		}
		CommandResult result = nxpMacCommand(cmd, hdr, encryptedData);
		byte[] decryptedResultData;
		if(result.data == null || result.data.length == 0) {
			decryptedResultData = result.data;
		} else {
			decryptedResultData = encryptionMode.decryptData(result.data);
		}

		return new CommandResult(decryptedResultData, result.status1, result.status2);
    }

	/**
	 * Runs a command, and the communication mode can be selected through the `mode` argument.
	 * @param mode
	 * @param cmd
	 * @param hdr
	 * @param data
	 * @return
	 * @throws IOException
	 */
	public CommandResult nxpSwitchedCommand(CommunicationMode mode, byte cmd, byte[] hdr, byte[] data) throws IOException {
		switch(mode) {
			case FULL:
				return nxpEncryptedCommand(cmd, hdr, data);
			case MAC:
				return nxpMacCommand(cmd, hdr, data);
			default:
				return nxpPlainCommand(cmd, hdr, data);
		}
    }
}