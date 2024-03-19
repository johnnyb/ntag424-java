package net.bplearning.ntag424;

public enum CommunicationMode {
	PLAIN,
	MAC,
	PLAIN_ALT,
	FULL;
	public byte getModeNumber() {
		switch(this) {
			case PLAIN:
			return 0;
			case MAC:
			return 1;
			case PLAIN_ALT:
			return 2;
			case FULL:
			return 3;
		}
		return 0; // should not reach this line
	}
}