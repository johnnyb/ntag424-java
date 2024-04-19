package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.exception.ProtocolException;
import net.bplearning.ntag424.util.ByteUtil;
import net.bplearning.ntag424.util.Crypto;

public class ChangeKey {
    // FIXME - need to change this to a boolean, but I don't know which result param means "bad old key".  9E?
    /**
     * Changes the given key.  If keyNum is 0, oldKey can be null.
     * User will be reauthenticated after changing key 0.
     */
	public static void run(DnaCommunicator communicator, int keyNum, byte[] oldKey, byte[] newKey, int keyVersion) throws IOException {
		if(communicator.getActiveKeyNumber() != 0) {
            throw new ProtocolException("Can only change keys from key 0");
        }

        if(keyNum == 0) {
            CommandResult result = communicator.nxpEncryptedCommand(
                (byte)0xc4,
				new byte[] { (byte)keyNum },
				ByteUtil.combineByteArrays(newKey, new byte[] { (byte)keyVersion })
            );
			result.throwUnlessSuccessful();

            // Success!  Need to restart authentication
            communicator.restartSession();
        } else {
            byte[] crc = Crypto.jamCrc32(newKey);
            byte[] xorkey = ByteUtil.xor(oldKey, newKey);
            CommandResult result = communicator.nxpEncryptedCommand(
				(byte)0xc4,
				new byte[] { (byte) keyNum },
                ByteUtil.combineByteArrays(xorkey, new byte[] { (byte)keyVersion }, crc)
            );
            
			result.throwUnlessSuccessful();
        }
	}
}
