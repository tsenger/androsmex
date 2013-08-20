package de.tsenger.androsmex;

import java.io.IOException;

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
import android.util.Log;
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
		
		
		prefs = PreferenceManager.getDefaultSharedPreferences(getBaseContext());
		registerPreferenceListener();

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
		
		// Register mMessageReceiver to receive messages.
		LocalBroadcastManager.getInstance(this).registerReceiver(mMessageReceiver, new IntentFilter("pace_finished"));
		
		//Register on sharedPrefs changes
		if (spListener==null) prefs.registerOnSharedPreferenceChangeListener(spListener);
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.i("Foreground dispatch", "Discovered tag with intent: " + intent);
		
		try {
			resolveIntent(intent);
		} catch (IOException e) {
			ergebnisText.append("ERROR:"+e.getMessage());
		}
	}

	@Override
	public void onPause() {
		super.onPause();
		mAdapter.disableForegroundDispatch(this);
		
		LocalBroadcastManager.getInstance(this).unregisterReceiver(mMessageReceiver);
		
		prefs.unregisterOnSharedPreferenceChangeListener(spListener);
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
			ergebnisText.append("EF.CardAccess:\n"+HexString.bufferToHex(efcaBytes)+"\n");
		} catch (Exception e1) {
			ergebnisText.append(e1.getMessage()+"\n");
		}
		return si;
	}
	

	private void resolveIntent(Intent intent) throws IOException {
		Tag discoveredTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);		
		if (discoveredTag != null) {			
			IsoDep isoDepTag = IsoDep.get(discoveredTag);
			idch = new IsoDepCardHandler(isoDepTag);
			
			ergebnisText.append("\nUID: " + HexString.bufferToHex(discoveredTag.getId())+"\nTag technologies:\n");
			String[] techList = discoveredTag.getTechList();
			for (int i=0;i<techList.length;i++) ergebnisText.append(i+1+": "+ techList[i]+"\n");
		}
	}
	
	
	private void performPACE(String pin) {	
		SecurityInfos si = getSecurityInfosFromCardAccess();		
		ptag = new PaceOperator(idch, getApplicationContext());	
		ptag.setAuthTemplate(si.getPaceInfoList().get(0), pin, ergebnisText, prefs);
		ergebnisText.append("Start PACE\n----------\n");
		ptag.execute((Void[])null).toString();
	}
	
	
	private void changePin() {
		TextView newPinText = (TextView) findViewById(R.id.input_newPin);
		String newPin = newPinText.getText().toString();
		if (idch.isSmActive()) {
			try {
				CommandAPDU capdu = CardCommands.resetRetryCounter((byte)0x03,newPin.getBytes());
				ergebnisText.append("Reset Retry Counter:\n"+HexString.bufferToHex(capdu.getBytes()));
				ergebnisText.append("Receive:\n"+HexString.bufferToHex(idch.transceive(capdu).getBytes()));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SecureMessagingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} else ergebnisText.append("Secure Messaging not active!");
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
	    Log.d("receiver", "Got message: " + message);
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
	    		Log.d("PrefListener","LISTENING! - Pref changed for: " + key + " pref: " + prefs.getString(key, null));
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