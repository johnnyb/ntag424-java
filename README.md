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

