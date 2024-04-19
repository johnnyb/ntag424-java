package net.bplearning.ntag424.constants;

public final class Ndef {
    /** Message begin flag */
    public static byte NDEF_MB = (byte)0b10000000;
    /** Message end flag */
    public static byte NDEF_ME = 0b01000000;
    /** Chunked flag */
    public static byte NDEF_CF = 0b00100000;
    /** Short record flag */
    public static byte NDEF_SR = 0b00010000;
    /** IL (ID Length) is present */
    public static byte NDEF_IL = 0b00001000;
    public static byte NDEF_TNF_EMPTY = 0x00;
    public static byte NDEF_TNF_WELL_KNOWN = 0x01;
    public static byte NDEF_TNF_MIME = 0x02;
    public static byte NDEF_TNF_ABSOLUTE_URI = 0x03; // NOTE - don't use this for URLS, use WELL_KNOWN instead.
    public static byte NDEF_TNF_EXTERNAL = 0x04;
    public static byte NDEF_TNF_UNKNOWN = 0x05;
    public static byte NDEF_TNF_UNCHANGED = 0x06;
    public static byte NDEF_TNF_RESERVED = 0x07;
    public static byte NDEF_TYPE_TEXT = 'T';
    public static byte NDEF_TYPE_URL = 'U';
}
