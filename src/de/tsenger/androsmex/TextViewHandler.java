package de.tsenger.androsmex;

import java.util.logging.Handler;
import java.util.logging.LogRecord;

import android.app.Activity;
import android.widget.TextView;

public class TextViewHandler extends Handler {
	
	private TextView tView=null;
	private Activity activity = null;

	public TextViewHandler(Activity activity, TextView tView) {
		super();
		this.activity = activity;
		this.tView = tView;
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

	@Override
	public void flush() {
		// TODO Auto-generated method stub

	}

	@Override
	public void publish(LogRecord arg0) {
		
		final LogRecord t1 = arg0;
		
		activity.runOnUiThread(new Runnable() {
		     public void run() {
		    	 tView.append(t1.getMessage()+"\n");
		     }
		});		

	}

}
