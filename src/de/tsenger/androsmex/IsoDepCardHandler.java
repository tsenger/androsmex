package de.tsenger.androsmex;

import java.io.IOException;

import android.nfc.tech.IsoDep;
import android.util.Log;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.tools.HexString;

public class IsoDepCardHandler implements CardHandler {
	
	private IsoDep tag = null;
	private SecureMessaging sm = null;
	
	public IsoDepCardHandler(IsoDep tag) throws IOException{
		this.tag = tag;
		if(!tag.isConnected()) {
			connectTag();
		}
		this.tag.setTimeout(3000);
	}
	
	private void connectTag() throws IOException {
			tag.connect();
	}
	
	public byte[] getUID() {
		return tag.getTag().getId();
	}
	
	public byte[] getTagInfo() {
		if (tag.getHistoricalBytes()!=null) return tag.getHistoricalBytes();
		else return tag.getHiLayerResponse();
	}
	
	public int getMaxTranceiveLength() {
		return tag.getMaxTransceiveLength();
	}

	@Override
	public boolean isConnected() {
		return tag.isConnected();
	}
		
	public void setSecureMessaging(SecureMessaging sm) {
		this.sm = sm;
	}
	
	public boolean isSmActive() {
		if(sm!=null) return true;
		else return false;
	}

	@Override
	public ResponseAPDU transceive(CommandAPDU cmd) throws IOException, SecureMessagingException  {
		byte[] rsp=null;
		if (!tag.isConnected()) tag.connect();
		if (sm!=null)cmd = sm.wrap(cmd);
		Log.d("CardHandler", "sent:\n"+HexString.bufferToHex(cmd.getBytes()));
		rsp = tag.transceive(cmd.getBytes());
		Log.d("CardHandler", "received:\n"+HexString.bufferToHex(rsp));
		ResponseAPDU rapdu = new ResponseAPDU(rsp);
		if (sm!=null)rapdu = sm.unwrap(rapdu);
		return rapdu;		
	}

}
