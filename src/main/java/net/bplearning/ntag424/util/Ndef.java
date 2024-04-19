package net.bplearning.ntag424.util;

public final class Ndef {
    public static byte[] ndefDataForUrlString(String urlString) {
        byte[] hdr = new byte[] {
                // See pgs. 30-31 of AN12196
                0x00,        // Placeholder for data size (two bytes MSB)
                0x00,        //
                (byte)(net.bplearning.ntag424.constants.Ndef.NDEF_MB | net.bplearning.ntag424.constants.Ndef.NDEF_ME | net.bplearning.ntag424.constants.Ndef.NDEF_SR | net.bplearning.ntag424.constants.Ndef.NDEF_TNF_WELL_KNOWN),  // NDEF header flags
                0x01,        // Length of "type" field
                0x00,        // URL size placeholder
                (byte) 0x55, // This will be a URL record
                0x00         // Just the URI (no prepended protocol)
        };
        byte[] urlBytes = urlString.getBytes();
        byte[] result = ByteUtil.combineByteArrays(hdr, urlBytes);
        result[1] = (byte)(result.length - 2);   // Length of everything that isn't the length
        result[4] = (byte)(urlBytes.length + 1); // Everything after type field

        return result;
    }
}
