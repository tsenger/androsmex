package de.tsenger.androsmex;

import java.io.IOException;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.PACETag;

public class JSmexMobileStartseite extends Activity {

	private NfcAdapter mAdapter;
	private PendingIntent mPendingIntent;
	private IntentFilter mFilters[];
	private String mTechLists[][];
	private final int mCount = 0;
	IsoDepCardHandler idch = null;

	TextView ergebnisText = null;
	Button buttonStart = null;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.jsmstartseite);

		ergebnisText = (TextView) findViewById(R.id.text_ergebnis);
		ergebnisText.setMovementMethod(new ScrollingMovementMethod());
		ergebnisText.setTypeface(Typeface.MONOSPACE);

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
			@Override
			public void onClick(View v) {
				
				TextView pinText = (TextView) findViewById(R.id.eingabe_mrz);
				if (pinText==null) return;
				PACETag ptag = new PACETag(idch, pinText.getText().toString(),ergebnisText);

				try {
					ptag.execute((Void[])null);
//					ptag.elCommand();
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
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.i("Foreground dispatch", "Discovered tag with intent: " + intent);
		ergebnisText.append("Discovered tag with intent: "
				+ intent);
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

	void resolveIntent(Intent intent) throws IOException {

		Tag discoveredTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		// Tag discoveredTag = intent.get;
		if (discoveredTag != null) {

			ergebnisText.setBackgroundColor(Color.LTGRAY);
			ergebnisText.setText("UID: "
					+ HexString.bufferToHex(discoveredTag.getId()));

			IsoDep isoDepTag = IsoDep.get(discoveredTag);
			idch = new IsoDepCardHandler(isoDepTag);

		}
	}

}