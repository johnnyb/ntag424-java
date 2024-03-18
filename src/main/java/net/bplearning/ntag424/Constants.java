package net.bplearning.ntag424;

import javax.crypto.spec.IvParameterSpec;

public class Constants {
	public static IvParameterSpec zeroIVPS = new IvParameterSpec(new byte[16]); // pg. 24
	public static byte[] upper = new byte[] { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	public static byte[] lower = new byte[]  { (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa };
	public static byte[] zeroBlock = new byte[16];
	public static byte[] fullPaddingBlock = new byte[] { (byte)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	public static int blockSize = 16;
	public static int nibbleSize = 4;


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
