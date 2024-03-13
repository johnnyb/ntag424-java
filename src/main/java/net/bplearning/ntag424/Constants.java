package net.bplearning.ntag424;

public class Constants {
	// Files on the card
	public static int CC_FILE_NUMBER = 0x01;
	public static int CC_FILE_ID = 0xe103;
	public static int NDEF_FILE_NUMBER = 0x02;
	public static int NDEF_FILE_ID = 0xe104;
	public static int DATA_FILE_NUMBER = 0x03;
	public static int DATA_FILE_ID = 0xe105;
	public static int PICC_FILE_ID = 0xe3f00;
	public static int DF_FILE_ID = 0xe110;
	public static byte[] DF_NAME = new byte[]{(byte)0xd2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01};	

	
}
