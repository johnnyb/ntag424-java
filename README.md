# NXP NTAG 424 DNA Library

This library is meant to help with handling the NXP NTAG 424 DNA chip.
Note that the library itself is completely hardware agnostic, and requires adding in a "transceiver" to manage the NFC hardware details.
See more about that in the Usage section.

Note that this is very much a work-in-progress and you should expect things to be moved around and renamed quite a bit for the time being.
The current API should not be considered stable.

This library is primarily based on the NXP document `NT4H2421Gx`, available [here](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf).
Page numbers (often referenced in the code) are from revision 3.0.

Note that this library was built almost entirely from the referenced documents.
I have no real experience with NFC, so I really don't know what is specific to this chip, to NXP generally, or to some other standard.
If you have suggestions on how to refactor this to support more NFC tags, I'm certainly open to it.

Note that there is a companion library for reading SUN messages that this chip can generate [here](https://github.com/johnnyb/nfc-sun-decoder).

Other important documents to read:

* Dna 424 Application Notes and hints, [NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
* Dna 424 LRP Mode Application Notes and hints, [NXP AN12321](https://www.nxp.com/docs/en/application-note/AN12321.pdf)

## Building

This library is built with Maven.  To build, just do:

```
mvn clean install
```

And it will produce a JAR file named `target/ntag424-VERSION.jar`. 

## Installing

To install, just copy the JAR built in the previous section into your JAR folder.  
For an Android project, this is usually in the `app/libs` directory.

## Usage

The intended usage of this library is within an Android project, though it is written so that it could be used with non-Android NFC hardware.
Basic information about NFC tag reading in Android is available [here](https://developer.android.com/develop/connectivity/nfc/nfc).
Assuming that you have discovered a tag through an Intent (named `tagIntent` in the code below), you can use the library as follows:

```
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;


...


Tag tag = tagIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
IsoDep iso = IsoDep.get(tag);
new Thread(() -> {
	try {
		iso.connect();

		// Connect the library to the Android tag transceiver
		DnaCommunicator communicator = new DnaCommunicator();
		communicator.setTransceiver((bytesToSend) -> iso.transceive(bytesToSend));

		// This is required to use the functionality of the chip.  It's a weird NFC thing.
		IsoSelectFile.run(communicator, IsoSelectFile.SELECT_MODE_BY_FILE_IDENTIFIER, Constants.DF_FILE_ID);

		// Try to authenticate with the factory key and start an encrypted session
		if(AESEncryptionMode.authenticateEV2(communicator, 0, Constants.FACTORY_KEY)) {
			// Run an encrypted command to get the Card UID
			byte[] cardUid = GetCardUid.run(communicator);
		} else {
			// Failed to authenticate
		}
	} catch(IOException e) {
		// Always expect IOExceptions - they can happen even from someone not holding the
		// tag in place long enough.
	}	
}).start();

```

The way the code works is that it is split into four basic parts:

1. The main DnaCommunicator class which handles packaging the commands for the communication channel, including encrypted session management.
2. Individual classes which each roughly correspond to a command in the spec.  These usually have one or more static methods named `run` which perform the task.  The first argument is always the DnaCommunicator object.  This was so that commands could be easily added without junking up the main DnaCommunicator class.  These currently reside in the `net.bplearning.ntag424.command` package.
3. Encryption mode classes.  These classes handle the actual encryption and MAC processing, with a static method that can be run to initiate the session.
4. Utility functions and constants.

## LRP Encryption

This library supports the LRP (leakage-resistant primitive) encryption mode.
However, you have to configure the tags to use LRP, and then, once they are in LRP mode, they *cannot* be switched back to AES mode.
To set a tag to LRP mode, authenticate (as shown above), and then do:
```
import net.bplearning.ntag424.command.SetCapabilities;

SetCapabilities.run(communicator, true);
```

After doing that, AES encryption mode will NOT be available on the tag, and you CANNOT get it back.
you will then need to change out your authentication function from `AESEncryptionMode.authenticateEV2` to `LRPEncryptionMode.authenticateLRP`.

The LRP encryption is based on the NXP Document `AN12304`, available [here](https://www.nxp.com/docs/en/application-note/AN12304.pdf).
Page numbers are from version 1.1.

Also note that there is a Go implementation of LRP available [here](https://github.com/johnnyb/gocrypto).

## Secure Dynamic Messaging (SDM)

This library has some utility functions for performing SDM and generating SUN (Secure Unique NFC) messages.

This is currently in flux, but the way it works right now is as follows:

1. Create an SDMSettings object
2. Set the file permissions on the SDMSettings object.
3. Create an NdefTemplateMaster object and set whether LRP is in use.
4. Create a structured URL using the components for SDM.
5. Pass the URL and the SDMSettings to the NdefTemplateMaster object and get the resulting file data.
6. Write the file data to the NDEF file.
7. Change the file settings on the NDEF file to use the new SDMSettings object.

Step 3 will probably be removed at some point and this functionality will be integrated into another class.  Probably.
We may also incorporate some special commands to make some of this easier.

Here is some example code:

```
// Generate a new SDMSettings object and set the access permissions
SDMSettings sdmSettings = new SDMSettings();
sdmSettings.sdmMetaReadPerm = Constants.ACCESS_EVERYONE; // Set to a key to get encrypted PICC data
sdmSettings.sdmFileReadPerm = Constants.ACCESS_KEY2;     // Used to create the MAC and Encrypt FileData
sdmSettings.sdmReadCounterRetrievalPerm = Constants.ACCESS_NONE; // Not sure what this is for

// Create the NDEF record and make appropriate updates to SDMSettings
byte[] ndefRecord = master.generateNdefTemplateFromUrlString("https://www.example.com/{UID}{COUNTER}/{MAC}", sdmSettings);

// Write the data to the NDEF file
WriteData.run(communicator, Constants.NDEF_FILE_NUMBER, ndefRecord);

// Get the existing file settings:
FileSettings ndeffs = GetFileSettings.run(communicator, Constants.NDEF_FILE_NUMBER);

// Make any modifications you would like to those settings/permissions
// ...

// Set the SDMSettings to the newly-created sdmSettings object
ndeffs.sdmSettings = sdmSettings;

// Make changes to the file
ChangeFileSettings.run(communicator, Constants.NDEF_FILE_NUMBER, ndeffs);
```

After this, your tag should be using SDM.  Note that the offsets will auto-expand to match the requirements of the template.
Template pieces include:

* `{UID}`: Mirror the UID here
* `{COUNTER}`: Mirror the SDM Read Counter here
* `{PICC}`: Put the encrypted PICC data here (encrypted with sdmMetaReadPerm key).  If set, be sure to set usesLrp on the NDefMasterTemplate object (affects the size of the PICC data).
* `{FILE}`: Put the encrypted file here (encrypted with sdmFileReadPerm key).  If set, be sure to set the fileDataLength of the NdefMasterTemplate object.
* `{MAC}`: Put the MAC data here.
* `^`: If set, this is the start of the location that will be used for MAC calculation.  If unset, it just becomes the locatin of the start of the MAC, indicating to only MAC the PICC data.

Personally, I like to use `{UID}{COUNTER}` and `{MAC}` rather than `{PICC}` because, if there is a connection issue with the Internet, I at least know what UID my tag was wanting to be.

## SDM Validation

You can also use this library on the "other side" to validate SDM messages and read their contents.
For unencrypted PICC data, do the following:

```
PiccData picc = new PiccData(uid, readCounter, usesLrp);
```

If the UID is not mirrored, set it to null.  If the readCounter is not mirrored, set it to 0.

For encrypted PICC data, do the following:

```
PiccData picc = PiccData.decodeFromEncryptedBytes(encryptedBytes, key, usesLrp);
```

Note that the key for decrypting the PICC data can be a different key from validating the MAC / decrypting the file data.
Therefore, you have to set this key with `setMacFileKey()`.

Then, you can validate the MAC (use an empty byte array for the message if there isn't one):

```
picc.setMacFileKey(macFileKey);
picc.performShortMac(new byte[0]); // MAC on PICC-only data
picc.decryptFileData(filedata);
```

## SDM Setups

This section describes some common ways to configure SDM.
SDM has a lot of options, so just picking a starting point is sometimes difficult.

Personally, my preferred method is to create an NDEF URL that looks like this: "https://www.example.com/tagread/{UID}{COUNTER}/{MAC}"

Basically, this puts the UID and counter in plaintext.
This means that if something is scanning but is not connected to the Internet, it can in fact read the UID off of the card.


## Key diversification

Key diversification allows you to have a different key on each device so that if someone were to steal the keys from the tag (which is itself a very difficult thing to do) it would not help them to know the keys for the other tags.

On the other hand, for key diversification to work, you need to know *which* key is on *which* device.
The standard way of doing this is by having a single master key which gets diversified by doing a CMAC using the master key with a combination of the tag's UID and some additional data known as the "diversification data" (this is used mostly to make sure the data is long enough to get a good CMAC).

Generally, the diversification data is constructed as follows.  
First, decide on a "system identifier".
This is a few bytes which is often an ASCII-ized version of your application name.
If your application is named "foo" then your system identifier is `new byte[] {0x66, 0x6f, 0x6f}`.
Then, use the `KeyInfo` class to construct your key.
Note that there is also an "application identifier" available.
I am not clear what that is supposed to be, but the document this is based on (AN10922) uses the "3-byte DESfire AID" (0x3042F5) in its example, so that is the default here.

```
byte[] masterKey = new byte[]{ /* ... */ };
KeyInfo keyInfo = new KeyInfo();
keyInfo.key = masterKey;
keyInfo.systemIdentifier = new byte[] {0x66, 0x6f, 0x6f};
byte[] cardKey = keyInfo.generateKeyForCardUid(uidBytes);
```

Note that usually the key that is used for encrypting PICC data (if any) is *not* diversified, because you need to know that key *before* you know the UID.
Then, once the UID is obtained, then that can be used to generate a UID-specific diversified key that is used for the file data encryption (if any) and the MAC (which is almost always used).

I think the general convention is to use App Key 2 for your non-diversified PICC encryption key, and then use App Key 3 for your diversified key.
Note, however, that your diversified key SHOULD NOT be just a diversification of your non-diversified key.
It should be based on a *separate* master key.
Otherwise, if someone were to decode one of your tags, obtaining the key would give them all the information they needed to generate and fake diversified keys.
Keeping the master key for your diversified keys secret is an absolute imperative for the system to work.
