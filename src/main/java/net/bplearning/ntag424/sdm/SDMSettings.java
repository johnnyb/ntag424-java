package net.bplearning.ntag424.sdm;

public class SDMSettings implements Cloneable {
	// SDM Options
	public boolean sdmEnabled = false;
    public boolean sdmOptionUid = false;
    public boolean sdmOptionReadCounter = false;
    public boolean sdmOptionEncryptFileData = false;
    public boolean sdmOptionUseAscii = true; // NOTE - Not sure the chip supports false
	public boolean sdmOptionReadCounterLimit = false;

	// SDM Permissions
    public int sdmMetaReadPerm = 0xe;
    public int sdmFileReadPerm = 0xe;
    public int sdmReadCounterRetrievalPerm = 0xe;
    
	// SDM Offsets
	public int sdmUidOffset = 0;
    public int sdmReadCounterOffset = 0;
    public int sdmPiccDataOffset = 0;
    public int sdmMacInputOffset = 0;
    public int sdmMacOffset = 0;
    public int sdmEncOffset = 0;
    public int sdmEncLength = 0;

    // SDM Limits
    public int sdmReadCounterLimit = 0;

    public SDMSettings duplicate() {
        try {
            return (SDMSettings) clone();
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
            return this;
        }
    }
}
