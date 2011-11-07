package de.tsenger.androsmex;

import java.io.IOException;


import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import de.tsenger.androsmex.pace.PACETag;
import de.tsenger.androsmex.tools.HexString;

public class AndroSmexStartseite extends Activity {

	private NfcAdapter mAdapter;
	private PendingIntent mPendingIntent;
	private IntentFilter mFilters[];
	private String mTechLists[][];
	IsoDepCardHandler idch = null;

	TextView ergebnisText = null;
	Button buttonStart = null;
	
	SharedPreferences prefs = null;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.startseite);
		
		ergebnisText = (TextView) findViewById(R.id.text_ergebnis);
		ergebnisText.setMovementMethod(new ScrollingMovementMethod());
		ergebnisText.setTypeface(Typeface.MONOSPACE);
		
		prefs = PreferenceManager.getDefaultSharedPreferences(getBaseContext());

		mAdapter = NfcAdapter.getDefaultAdapter(this);

		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
				getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

		IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
		try {
			ndef.addDataType("*/*");
		} catch (MalformedMimeTypeException e) {
			throw new RuntimeException("fail", e);
		}
		mFilters = new IntentFilter[] { ndef, };

		mTechLists = new String[][] { new String[] { IsoDep.class.getName() } };

		View.OnClickListener eventHandler = new View.OnClickListener() {
			public void onClick(View v) {
				
				TextView pinText = (TextView) findViewById(R.id.eingabe_mrz);
				if (pinText==null) return;
				PACETag ptag = new PACETag(idch, pinText.getText().toString(),ergebnisText, prefs);

				try {
					
					ptag.execute((Void[])null);
				} catch (Exception e) {
					ergebnisText.append(e.getMessage()+"\n"+e.getClass().getCanonicalName());
					ergebnisText.setBackgroundColor(Color.RED);
				}

			}
		};

		buttonStart = (Button) findViewById(R.id.button_start);
		buttonStart.setOnClickListener(eventHandler);
	}

	@Override
	public void onResume() {
		super.onResume();
		mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters,
				mTechLists);
		TextView password_info = (TextView) findViewById(R.id.textView1);
		int i = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		switch (i) {
		case 1: password_info.setText("MRZ"); break;
		case 2: password_info.setText("CAN"); break;
		case 3: password_info.setText("PIN"); break;
		case 4: password_info.setText("PUK"); break;
		}
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

	

	private void resolveIntent(Intent intent) throws IOException {

		Tag discoveredTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		// Tag discoveredTag = intent.get;
		if (discoveredTag != null) {

			ergebnisText.setBackgroundColor(Color.LTGRAY);
			ergebnisText.append("\nUID: "
					+ HexString.bufferToHex(discoveredTag.getId())+"\nTag technologies:\n");
			String[] techList = discoveredTag.getTechList();
			for (int i=0;i<techList.length;i++) ergebnisText.append(i+1+": "+ techList[i]+"\n");

			IsoDep isoDepTag = IsoDep.get(discoveredTag);
			idch = new IsoDepCardHandler(isoDepTag);

		}
	}

}