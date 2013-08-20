package de.tsenger.androsmex;

import java.util.logging.Handler;
import java.util.logging.LogRecord;

import android.widget.TextView;

public class TextViewHandler extends Handler {
	
	private TextView tView=null;

	public TextViewHandler(TextView tView) {
		super();
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
		tView.append(arg0.getMessage()+"\n");

	}

}
