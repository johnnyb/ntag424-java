package com.bplearning.ntag424demo;

import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.bplearning.ntag424demo.databinding.ActivityMainBinding;

import android.view.Menu;
import android.view.MenuItem;

import net.bplearning.ntag424.Constants;
import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.Util;
import net.bplearning.ntag424.card.KeyInfo;
import net.bplearning.ntag424.card.KeySet;
import net.bplearning.ntag424.command.ChangeFileSettings;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.command.WriteData;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    public static final String LOG_TAG = "NfcApp";

    private AppBarConfiguration appBarConfiguration;
    private ActivityMainBinding binding;

    // Boilerplate - ignore
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setSupportActionBar(binding.toolbar);

        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        appBarConfiguration = new AppBarConfiguration.Builder(navController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfiguration);

        binding.fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
    }

    // Boilerplate - ignore
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    // Boilerplate - ignore
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    // Boilerplate - ignore
    @Override
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        return NavigationUI.navigateUp(navController, appBarConfiguration)
                || super.onSupportNavigateUp();
    }

    // This one is important - register for NFC intents when the screen is active
    @Override
    protected void onResume() {
        super.onResume();

        registerActivityForNfcIntents();
    }


    // Deregister when screen is no longer active
    @Override
    protected void onPause() {
        super.onPause();
        deregisterActivityForNfcIntents();
    }


    // This gets called when we get an intent
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Log.d(LOG_TAG, "New intent received: " + intent.getAction());
        if(intent != null) {
            handleIncomingIntent(intent);
        }
    }

    /** App Methods **/

    // Registration and deregistration

    public void registerActivityForNfcIntents() {
        // Tell the NFC adapter to send us any intents that it receives
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if(adapter != null) {
            Log.d(LOG_TAG, "Found adapter: registering for intents");
            Intent launchIntent = new Intent(this.getApplicationContext(), MainActivity.class);
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

            PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, launchIntent, PendingIntent.FLAG_CANCEL_CURRENT);
            adapter.enableForegroundDispatch(this, pendingIntent, null, null);
        }
    }

    public void deregisterActivityForNfcIntents() {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if(adapter != null) {
            adapter.disableForegroundDispatch(this);
        }
    }


    // NFC events come in as intents.  Processes intents that it recognizes.
    public static String[] nfcActions = { NfcAdapter.ACTION_TAG_DISCOVERED, NfcAdapter.ACTION_NDEF_DISCOVERED, NfcAdapter.ACTION_TECH_DISCOVERED };
    public void handleIncomingIntent(@NonNull Intent i) {
        String action = i.getAction();
        for(String nfcAction: nfcActions) {
            if(nfcAction.equals(action)) {
                Log.d(LOG_TAG, "Received NFC Intent: " + action);
                handleNfcIntent(i);
            }
        }
    }

    // We have an NFC event - do stuff
    public void handleNfcIntent(@NonNull Intent i) {
        Tag tag = i.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        showTagInfo(tag);
        communicateWithTag(tag);
    }

    public void showNdefMessages(NdefMessage[] ndefMessages) {
        if(ndefMessages == null) {
            Log.d(LOG_TAG, "No NDEF messages");
            return;
        }
        for(NdefMessage msg: ndefMessages) {
            Log.d(LOG_TAG, "NDEF: " + msg.toString());
            NdefRecord[] records = msg.getRecords();
            if(records == null) {
                Log.d(LOG_TAG, "No NDEF Records");
                continue;
            }
            for(NdefRecord rec: msg.getRecords()) {
                Log.d(LOG_TAG, "NDEFREC: " + rec.toString());
            }
        }
    }


    // Basic publicly-viewable tag information
    public void showTagInfo(Tag tag) {
        Log.d(LOG_TAG, "Tag ID: " + Util.byteToHex(tag.getId()));
        Log.d(LOG_TAG, "Tag Tech: " + String.join(", ", tag.getTechList()));
    }

    public KeySet getKeySet() {
        // NOTE - replace these with your own keys.
        //
        //        Any of the keys *can* be diversified
        //        if you don't use RandomID, but usually
        //        only the MAC key is diversified.

        KeySet keySet = new KeySet();
        keySet.setUsesLrp(false);

        // This is the "master" key
        KeyInfo key0 = new KeyInfo();
        key0.diversifyKeys = false;
        key0.key = Constants.FACTORY_KEY;
        keySet.setKey(Constants.ACCESS_KEY0, key0);

        // No standard usage
        KeyInfo key1 = new KeyInfo();
        key1.diversifyKeys = false;
        key1.key = Constants.FACTORY_KEY;
        keySet.setKey(Constants.ACCESS_KEY1, key1);

        // Usually used as a meta read key for encrypted PICC data
        KeyInfo key2 = new KeyInfo();
        key2.diversifyKeys = false;
        key2.key = Constants.FACTORY_KEY;
        keySet.setKey(Constants.ACCESS_KEY2, key2);

        // Usually used as the MAC and encryption key.
        // The MAC key usually has the diversification information setup.
        KeyInfo key3 = new KeyInfo();
        key3.diversifyKeys = true;
        key3.systemIdentifier = new byte[] { 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67 }; // systemIdentifier is usually a hex-encoded string.  Here, it is "testing".
        key3.key = Constants.FACTORY_KEY;

        // No standard usage
        keySet.setKey(Constants.ACCESS_KEY3, key3);
        KeyInfo key4 = new KeyInfo();
        key4.diversifyKeys = false;
        key4.key = Constants.FACTORY_KEY;
        keySet.setKey(Constants.ACCESS_KEY4, key4);

        // This is used for decoding, but documenting that key2/key3 are standard for meta and mac
        keySet.setMetaKey(Constants.ACCESS_KEY2);
        keySet.setMacFileKey(Constants.ACCESS_KEY3);

        return keySet;
    }

    // This is the nitty-gritty
    public void communicateWithTag(Tag tag) {
        // IsoDep runs the communication with the tag
        IsoDep iso = IsoDep.get(tag);

        // Communication needs to be on its own thread
        new Thread(() -> {
            try {
                // Standard NFC connect
                iso.connect();

                // Initialize DNA library
                DnaCommunicator communicator = new DnaCommunicator();
                communicator.setTransceiver((bytesToSend) -> iso.transceive(bytesToSend));
                communicator.setLogger((info) -> Log.d(LOG_TAG, "Communicator: " + info));
                communicator.beginCommunication();


                // Authenticate with a key.  If you are in LRP mode (Requires permanently changing tag settings), uncomment the LRP version instead.
                // if(LRPEncryptionMode.authenticateLRP(communicator, 0, Constants.FACTORY_KEY)) {
                if(AESEncryptionMode.authenticateEV2(communicator, 0, Constants.FACTORY_KEY)) {
                    Log.d(LOG_TAG, "Login successful");
                    byte[] cardUid = GetCardUid.run(communicator);
                    Log.d(LOG_TAG, "Card UID: " + Util.byteToHex(cardUid));
                    int keyVersion = GetKeyVersion.run(communicator, 0);
                    Log.d(LOG_TAG, "Key 0 version: " + keyVersion);

                    KeySet keySet = getKeySet();
                    keySet.synchronizeKeys(communicator);

                    // Doing this will set LRP mode for all future authentications
                    // SetCapabilities.run(communicator, true);

                    // Get the NDEF file settings
                    FileSettings ndeffs = GetFileSettings.run(communicator, Constants.NDEF_FILE_NUMBER);
                    Log.d(LOG_TAG, "Debug NDEF: " + debugStringForFileSettings(ndeffs));

                    // Secret data
                    byte[] secretData = new byte[] {
                            1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
                    };

                    // Set the access keys and options
                    SDMSettings sdmSettings = new SDMSettings();
                    sdmSettings.sdmMetaReadPerm = Constants.ACCESS_KEY2; // Set to a key to get encrypted PICC data
                    sdmSettings.sdmFileReadPerm = Constants.ACCESS_KEY2;     // Used to create the MAC and Encrypt FileData
                    sdmSettings.sdmOptionUid = true;
                    sdmSettings.sdmOptionReadCounter = true;

                    // NDEF SDM formatter helper - uses a template to write SDMSettings and get file data
                    NdefTemplateMaster master = new NdefTemplateMaster();
                    master.usesLRP = false;
                    byte[] ndefRecord = master.generateNdefTemplateFromUrlString("https://www.example.com/{PICC}/{FILE}/{MAC}", secretData, sdmSettings);

                    // Write the record to the file
                    WriteData.run(communicator, Constants.NDEF_FILE_NUMBER, ndefRecord);

                    // Set the general NDEF permissions
                    ndeffs.readPerm = Constants.ACCESS_EVERYONE;
                    ndeffs.writePerm = Constants.ACCESS_KEY0;
                    ndeffs.readWritePerm = Constants.ACCESS_KEY3; // backup key
                    ndeffs.changePerm = Constants.ACCESS_KEY0;
                    ndeffs.sdmSettings = sdmSettings; // Use the SDM settings we just setup
                    Log.d(LOG_TAG, "New Ndef Settings: " + debugStringForFileSettings(ndeffs));
                    ChangeFileSettings.run(communicator, Constants.NDEF_FILE_NUMBER, ndeffs);
                } else {
                    Log.d(LOG_TAG, "Login unsuccessful");
                }

                // We are done
                iso.close();
                Log.d(LOG_TAG, "Disconnected from tag");
            } catch (IOException e) {
                Log.d(LOG_TAG, "error communicating", e);
            }
        }).start();
    }


    // Make file permission/SDM settings easier to see in the logs
    public String debugStringForFileSettings(FileSettings fs) {
        StringBuilder sb = new StringBuilder();
        sb.append("= FileSettings =").append("\n");
        sb.append("fileType: ").append("n/a").append("\n"); // todo expose get file type for DESFire
        sb.append("commMode: ").append(fs.commMode.toString()).append("\n");
        sb.append("accessRights RW:       ").append(fs.readWritePerm).append("\n");
        sb.append("accessRights CAR:      ").append(fs.changePerm).append("\n");
        sb.append("accessRights R:        ").append(fs.readPerm).append("\n");
        sb.append("accessRights W:        ").append(fs.writePerm).append("\n");
        sb.append("fileSize: ").append(fs.fileSize).append("\n");
        sb.append("= Secure Dynamic Messaging =").append("\n");
        sb.append("isSdmEnabled: ").append(fs.sdmSettings.sdmEnabled).append("\n");
        sb.append("isSdmOptionUid: ").append(fs.sdmSettings.sdmOptionUid).append("\n");
        sb.append("isSdmOptionReadCounter: ").append(fs.sdmSettings.sdmOptionReadCounter).append("\n");
        sb.append("isSdmOptionReadCounterLimit: ").append(fs.sdmSettings.sdmOptionReadCounterLimit).append("\n");
        sb.append("isSdmOptionEncryptFileData: ").append(fs.sdmSettings.sdmOptionEncryptFileData).append("\n");
        sb.append("isSdmOptionUseAscii: ").append(fs.sdmSettings.sdmOptionUseAscii).append("\n");
        sb.append("sdmMetaReadPerm:             ").append(fs.sdmSettings.sdmMetaReadPerm).append("\n");
        sb.append("sdmFileReadPerm:             ").append(fs.sdmSettings.sdmFileReadPerm).append("\n");
        sb.append("sdmReadCounterRetrievalPerm: ").append(fs.sdmSettings.sdmReadCounterRetrievalPerm).append("\n");
        sb.append("sdmUidOffset:         ").append(fs.sdmSettings.sdmUidOffset).append("\n");
        sb.append("sdmReadCounterOffset: ").append(fs.sdmSettings.sdmReadCounterOffset).append("\n");
        sb.append("sdmPiccDataOffset:    ").append(fs.sdmSettings.sdmPiccDataOffset).append("\n");
        sb.append("sdmMacInputOffset:    ").append(fs.sdmSettings.sdmMacInputOffset).append("\n");
        sb.append("sdmMacOffset:         ").append(fs.sdmSettings.sdmMacOffset).append("\n");
        sb.append("sdmEncOffset:         ").append(fs.sdmSettings.sdmEncOffset).append("\n");
        sb.append("sdmEncLength:         ").append(fs.sdmSettings.sdmEncLength).append("\n");
        sb.append("sdmReadCounterLimit:  ").append(fs.sdmSettings.sdmReadCounterLimit).append("\n");
        return sb.toString();
    }
}
