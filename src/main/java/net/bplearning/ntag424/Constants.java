package net.bplearning.ntag424;

import javax.crypto.spec.IvParameterSpec;

public class Constants {
	public static IvParameterSpec zeroIVPS = new IvParameterSpec(new byte[16]); // pg. 24
	public static byte[] upper = new byte[] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	public static byte[] lower = new byte[]  { (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa };
	public static byte[] zeroBlock = new byte[16];
	public static byte[] fullPaddingBlock = new byte[] { (byte)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	public static byte marker = (byte)0x80;
	public static int blockSize = 16;
	public static int nibbleSize = 4;

	public static boolean[] RB_128; static {
		RB_128 = new boolean[128];
		RB_128[120] = true;
		RB_128[125] = true;
		RB_128[126] = true;
		RB_128[127] = true;
	}

	public static boolean[] RB_64; static {
		RB_64 = new boolean[64];
		RB_64[59] = true;
		RB_64[60] = true;
		RB_64[62] = true;
		RB_64[63] = true;
	}

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

	public static byte[] FACTORY_KEY = new byte[16];
}
