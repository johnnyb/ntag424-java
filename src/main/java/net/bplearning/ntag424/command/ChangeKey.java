package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.exception.ProtocolException;

public class ChangeKey {
	public void run(DnaCommunicator communicator, int keyNum, byte[] oldKey, byte[] newKey, int keyVersion) throws IOException {
		if(communicator.getActiveKeyNumber() != 0) {
            throw new ProtocolException("Can only change keys from key 0");
        }

        if(keyNum == 0) {
            CommandResult result = communicator.nxpEncryptedCommand(
                (byte)0xc4,
				new byte[] { (byte)keyNum },
				Util.combineByteArrays(newKey, new byte[] { (byte)keyVersion })
            );
			result.throwUnlessSuccessful();
        } else {
            byte[] crc = Util.jamCrc32(newKey);
            byte[] xorkey = Util.xor(oldKey, newKey);
            CommandResult result = communicator.nxpEncryptedCommand(
				(byte)0xc4,
				new byte[] { (byte) keyNum },
                Util.combineByteArrays(xorkey, new byte[] { (byte)keyVersion }, crc)
            );
			result.throwUnlessSuccessful();
        }
	}
}
