package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class ChangeFileSettings implements Command {
    /** 
     * Runs the ChangeFileSettings command. 
     * Note that this command has a lot of restrictions. 
     * If you get a 919E result, you should check the data sheet (NT4H2421Gx pgs. 68-69) to see what is being set incorrectly.
     */
	public static void run(DnaCommunicator communicator, int fileNum, FileSettings settings) throws IOException {
        byte[] data = settings.encodeToData();

        CommandResult result = communicator.nxpEncryptedCommand(
            (byte)0x5f,
			new byte[] { (byte) fileNum },
            data
        );
		result.throwUnlessSuccessful();
    }
}
