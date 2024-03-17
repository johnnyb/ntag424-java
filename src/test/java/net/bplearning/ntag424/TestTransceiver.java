package net.bplearning.ntag424;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class TestTransceiver implements DnaCommunicator.ThrowableFunction<byte[], byte[], IOException> {
	public List<byte[]> responses = new LinkedList<>();
	public int lastResponseIndex = -1;
	public List<byte[]> recordedRequests = new LinkedList<>();

	@Override
	public byte[] apply(byte[] input) throws IOException {
		recordedRequests.add(input);
		lastResponseIndex++;

		if(lastResponseIndex >= responses.size()) {
			return new byte[0];
		}

		return responses.get(lastResponseIndex);
	}
}
