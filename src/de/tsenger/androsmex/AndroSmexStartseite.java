package de.tsenger.androsmex;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.content.LocalBroadcastManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.ScrollingMovementMethod;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import de.tsenger.androsmex.asn1.SecurityInfos;
import de.tsenger.androsmex.iso7816.CardCommands;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.FileAccess;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.pace.PaceOperator;
import de.tsenger.androsmex.tools.HexString;

public class AndroSmexStartseite extends Activity{

	private NfcAdapter mAdapter;
	private PendingIntent mPendingIntent;
	private IntentFilter mFilters[];
	private String mTechLists[][];
	IsoDepCardHandler idch = null;
	PaceOperator ptag = null;

	TextView ergebnisText = null;
	TextWatcher tWatcher = null;
	
	Button buttonStart = null;
	
	SharedPreferences prefs = null;
	OnSharedPreferenceChangeListener spListener = null;
	
	private String nextAction;
	
	 private static final Logger asLogger = Logger.getLogger("AndroSmex");
	
	
	/**
	 * Handler for "Start PACE"-Button
	 * @param v
	 */	
	public void onClickStartPACE(View v) {		
		TextView pinText = (TextView) findViewById(R.id.input_password);
		String pin = pinText.getText().toString();
		if (pin.equals("")) return;
		performPACE(pin);
	}
	
	/**
	 * Handler for "Change PIN"-Button
	 * @param v
	 */		
	public void onClickChangePIN(View v) {
		
		TextView pinText = (TextView) findViewById(R.id.input_password);
		TextView newPinText = (TextView) findViewById(R.id.input_newPin);
		String pin = pinText.getText().toString();
		String newPin = newPinText.getText().toString();
		if (pin.equals("")||newPin.equals("")) return;
		
		int passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		int terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));
		if (passwordRef!=3||terminalType!=0) return;
		
		performPACE(pin);
		nextAction = "changePIN";
		
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.startseite);
		
		ergebnisText = (TextView) findViewById(R.id.text_ergebnis);
		ergebnisText.setMovementMethod(new ScrollingMovementMethod());
		ergebnisText.setTypeface(Typeface.MONOSPACE);
		registerTextChangedListerner();
		
		// Set up Preferences		
		prefs = PreferenceManager.getDefaultSharedPreferences(getBaseContext());
		registerPreferenceListener();

		//Set up NFC Intents
		mAdapter = NfcAdapter.getDefaultAdapter(this);
		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
		IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
		try {
			ndef.addDataType("*/*");
		} catch (MalformedMimeTypeException e) {
			throw new RuntimeException("fail", e);
		}
		mFilters = new IntentFilter[] { ndef, };
		mTechLists = new String[][] { new String[] { IsoDep.class.getName() } };
		
		//Set up Logger to TextView
		TextViewHandler handler = new TextViewHandler(this, ergebnisText);
		asLogger.addHandler(handler);
		asLogger.setLevel(Level.parse(prefs.getString("pref_list_log", "INFO")));
		
		// Register mMessageReceiver to receive local messages.
		LocalBroadcastManager.getInstance(this).registerReceiver(mMessageReceiver, new IntentFilter("pace_finished"));
	}


	@Override
	public void onResume() {
		super.onResume();
		mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters, mTechLists);
		TextView password_info = (TextView) findViewById(R.id.textView1);
		int i = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		switch (i) {
		case 1: password_info.setText("MRZ"); break;
		case 2: password_info.setText("CAN"); break;
		case 3: password_info.setText("PIN"); break;
		case 4: password_info.setText("PUK"); break;
		}
		
		asLogger.setLevel(Level.parse(prefs.getString("pref_list_log", "INFO")));
		
		// Register mMessageReceiver to receive messages.
		LocalBroadcastManager.getInstance(this).registerReceiver(mMessageReceiver, new IntentFilter("pace_finished"));
		
		//Register on sharedPrefs changes
//		if (spListener==null) prefs.registerOnSharedPreferenceChangeListener(spListener);
	}

	@Override
	public void onNewIntent(Intent intent) {
		asLogger.log(Level.FINER, "onNewIntent discovered tag with intent: " + intent);
		
		try {
			resolveIntent(intent);
		} catch (IOException e) {
			asLogger.log(Level.SEVERE, "onNewIntent throwed IOException", e);
		}
	}

	@Override
	public void onPause() {
		super.onPause();
		mAdapter.disableForegroundDispatch(this);		
		LocalBroadcastManager.getInstance(this).unregisterReceiver(mMessageReceiver);		
//		prefs.unregisterOnSharedPreferenceChangeListener(spListener);
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
	    MenuInflater inflater = getMenuInflater();
	    inflater.inflate(R.menu.options_menu, menu);
	    return true;
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
	    // Handle item selection
	    switch (item.getItemId()) {
	    case R.id.clear_log:
	    	ergebnisText.setText("");
	        return true;
	    case R.id.settings:
	    	Intent intent = new Intent(this, AndroSmexKonfiguration.class);
	    	startActivity(intent);
	        return true;
	    default:
	        return super.onOptionsItemSelected(item);
	    }
	}

	
	private SecurityInfos getSecurityInfosFromCardAccess() {		
		byte[] fid_efca = new byte[]{(byte) 0x01, (byte)0x1C};
		FileAccess facs = new FileAccess(idch);
		byte[] efcaBytes = null;
		SecurityInfos si = null;		
		try {
			efcaBytes = facs.getFile(fid_efca);
			si = new SecurityInfos();
			si.decode(efcaBytes);
			asLogger.log(Level.FINE, "Content of EF.CardAccess:\n"+HexString.bufferToHex(efcaBytes));
		} catch (Exception e1) {
			asLogger.log(Level.WARNING, "getSecurityInfosFromCardAccess() throws exception", e1);
		}
		return si;
	}
	

	private void resolveIntent(Intent intent) throws IOException {
		Tag discoveredTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);		
		if (discoveredTag != null) {			
			IsoDep isoDepTag = IsoDep.get(discoveredTag);
			idch = new IsoDepCardHandler(isoDepTag, asLogger);
			
			asLogger.log(Level.INFO, "Tag ID: " + HexString.bufferToHex(discoveredTag.getId()));
			String[] techList = discoveredTag.getTechList();
			asLogger.log(Level.FINER, "Tag technologies:");
			for (int i=0;i<techList.length;i++) asLogger.log(Level.FINER, i+1+": "+ techList[i]);
		}
	}
	
	
	private void performPACE(String pin) {	
		SecurityInfos si = getSecurityInfosFromCardAccess();		
		ptag = new PaceOperator(idch, getApplicationContext());	
		ptag.setAuthTemplate(si.getPaceInfoList().get(0), pin, asLogger, prefs);
		asLogger.log(Level.INFO, "Start PACE");
		ptag.execute((Void[])null);
	}
	
	
	private void changePin() {
		TextView newPinText = (TextView) findViewById(R.id.input_newPin);
		String newPin = newPinText.getText().toString();
		if (idch.isSmActive()) {
			asLogger.log(Level.INFO, "Send Reset Retry Counter command");
			try {
				CommandAPDU capdu = CardCommands.resetRetryCounter((byte)0x03,newPin.getBytes());
				ResponseAPDU rapdu = idch.transceive(capdu);
				if (rapdu.getSW()==0x9000) asLogger.log(Level.INFO, "PIN changed successful");
				else asLogger.log(Level.INFO, "changing PIN failed");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SecureMessagingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} else asLogger.log(Level.INFO, "Couldn't change PIN: Secure Messaging not active!");
	}
	
	
	private void nextActionSwitcher() {
		if (nextAction == null) return;
		if (nextAction.equals("changePIN")) changePin();
		nextAction = null;
	}
	
	
	// handler for received Intents for the "pace_finished_event" 
	private BroadcastReceiver mMessageReceiver = new BroadcastReceiver() {
	  @Override
	  public void onReceive(Context context, Intent intent) {
	    // Extract data included in the Intent
	    String message = intent.getStringExtra("message");
	    asLogger.log(Level.INFO, message);
	    nextActionSwitcher();
	  }
	};
	
	
	private void registerTextChangedListerner() {
		tWatcher = new TextWatcher(){
			@Override
			public void afterTextChanged(Editable s) {
				TextView smIndicator = (TextView) findViewById(R.id.textView_SM_Indicator);
			    if (idch!=null&&idch.isSmActive()) {	    	
			    	smIndicator.setBackgroundColor(Color.GREEN);
			    	smIndicator.setText(getString(R.string.status_sm_active));
			    } else {
			    	smIndicator.setBackgroundColor(Color.parseColor("#FFE0E00F"));
			    	smIndicator.setText(getString(R.string.status_sm_inactive));
			    }
	        }
	        public void beforeTextChanged(CharSequence s, int start, int count, int after){}
	        public void onTextChanged(CharSequence s, int start, int before, int count){}
	    }; 
	    ergebnisText.addTextChangedListener(tWatcher);
	}
	
	
	private void registerPreferenceListener()	{		 
		spListener = new SharedPreferences.OnSharedPreferenceChangeListener() {
	    	public void onSharedPreferenceChanged(SharedPreferences prefs, String key) {
	    		asLogger.log(Level.FINER, "Pref changed for: " + key + " to " + prefs.getString(key, null));
	    		
	    		asLogger.setLevel(Level.parse(prefs.getString("pref_list_log", "INFO")));
	    		
	    		int passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
	    		int terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));

	    		Button chgPinButton = (Button) findViewById(R.id.button_chgpin);
	    		TextView chgPinTV = (TextView) findViewById(R.id.input_newPin);
	    		if (passwordRef!=3||terminalType!=0) {
	    			chgPinButton.setEnabled(false);
	    			chgPinTV.setEnabled(false);
	    		} else {
	    			chgPinButton.setEnabled(true);
	    			chgPinTV.setEnabled(true);
	    		}
	    	}
	    };
	    prefs.registerOnSharedPreferenceChangeListener(spListener);
	}

}