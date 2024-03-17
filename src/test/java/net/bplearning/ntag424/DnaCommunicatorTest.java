package net.bplearning.ntag424;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;

import org.junit.Test;

public class DnaCommunicatorTest {
	@Test
	public void testInitialCommunication() throws IOException {
		DnaCommunicator communicator = new DnaCommunicator();
		TestTransceiver transceiver = new TestTransceiver();
		communicator.setTransceiver(transceiver);
		communicator.beginCommunication();
		assertArrayEquals(new byte[] {0x00,(byte)0xa4,0x00,0x0c,0x02,(byte)0xe1,0x10,0x00}, transceiver.recordedRequests.get(0));
	}
}
