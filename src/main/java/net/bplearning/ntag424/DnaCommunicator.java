package net.bplearning.ntag424;

import java.util.function.Consumer;
import java.util.function.Function;

import net.bplearning.ntag424.encryptionmode.EncryptionMode;

public class DnaCommunicator {
	public DnaCommunicator(Function<byte[], byte[]> newTransceiver) { 
		transceiver = newTransceiver;
	}

	protected Function<byte[], byte[]> transceiver;
	protected EncryptionMode sessionEncryptionMode;
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

	public static class CommandResult {
		public byte[] data;
		public byte status1;
		public byte status2;

		public CommandResult(byte[] rawData) {
			data = new byte[rawData.length - 2];
			System.arraycopy(rawData, 0, data, 0, data.length);
			status1 = rawData[rawData.length - 2];
			status2 = rawData[rawData.length - 1];
		}
	}
	
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
		int endIndex = results.length - 1;
		return new CommandResult(results);
    }
}