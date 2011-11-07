package de.tsenger.androsmex;

import android.os.Bundle;
import android.preference.PreferenceActivity;

public class AndroSmexKonfiguration extends PreferenceActivity {

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.xml.preferences);
	}
	



}
