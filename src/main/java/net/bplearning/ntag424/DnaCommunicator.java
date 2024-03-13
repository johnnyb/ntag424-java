package net.bplearning.ntag424;

import java.util.function.Consumer;
import java.util.function.Function;

import net.bplearning.ntag424.encryptionmode.EncryptionMode;
import net.bplearning.ntag424.exception.MACValidationException;
import net.bplearning.ntag424.exception.ProtocolException;

public class DnaCommunicator {
	public DnaCommunicator(Function<byte[], byte[]> newTransceiver) { 
		transceiver = newTransceiver;
	}

	protected Function<byte[], byte[]> transceiver;
	protected EncryptionMode encryptionMode;
	protected byte[] activeTransactionIdentifier;
	protected int activeKeyNumber;
	protected int commandCounter;
	protected Consumer<String> log = (val) -> {};

	protected byte[] transceive(byte[] bytesToSend) {
		return transceiver.apply(bytesToSend);
	}

	public byte[] getActiveTransactionIdentifier() {
		return activeTransactionIdentifier;
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

	/**
	 * Runs a basic framed NXP native command.
	 * Does not affect the command counter.
	 */
	public CommandResult nxpNativeCommand(byte cmd, byte[] hdr, byte[] data, byte[] macData) {
		byte[] command = new byte[] {
			(byte)0x90,
			(byte)cmd,
			(byte)0x00,
			(byte)0x00,
			(byte)(hdr.length + data.length + macData.length)
		};

		command = Util.combineByteArrays(
			command, 
			hdr,
			data,
			macData,
			new byte[]{0x00}
		);

		byte[] results = transceive(command);
		return new CommandResult(results);
    }

	/**
	 * Runs a plain, unencrypted command.
	 * @param cmd
	 * @param hdr
	 * @param data
	 * @return
	 */
	public CommandResult nxpPlainCommand(byte cmd, byte[] hdr, byte[] data) {
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
	public CommandResult nxpMacCommand(byte cmd, byte[] hdr, byte[] data) throws ProtocolException {
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
        int sz = data.length;
        if(sz < 8) {
			return new CommandResult(new byte[0], result.status1, result.status2);
        }

        byte[] dataBytes = Util.subArrayOf(data, 0, sz - 8);
        byte[] macBytes = Util.subArrayOf(data, sz - 8, 8);

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
	public CommandResult nxpEncryptedCommand(byte cmd, byte[] hdr, byte[] data) throws ProtocolException {
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
	 * @throws ProtocolException
	 */
	public CommandResult nxpSwitchedCommand(CommunicationMode mode, byte cmd, byte[] hdr, byte[] data) throws ProtocolException {
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