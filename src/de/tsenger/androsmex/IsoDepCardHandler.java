package de.tsenger.androsmex;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import android.nfc.tech.IsoDep;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.tools.HexString;

public class IsoDepCardHandler implements CardHandler {
	
	private IsoDep tag = null;
	private SecureMessaging sm = null;
	private Logger logger = null;
	
	public IsoDepCardHandler(IsoDep tag, Logger logger) throws IOException {	
		this.logger = logger;
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
		
		logger.log(Level.FINE, "sent (PLAIN):\n"+HexString.bufferToHex(cmd.getBytes()));
		if (sm!=null) {
			cmd = sm.wrap(cmd);
			logger.log(Level.FINE, "sent (SM):\n"+HexString.bufferToHex(cmd.getBytes()));
		}		
		
		rsp = tag.transceive(cmd.getBytes());
		ResponseAPDU rapdu = new ResponseAPDU(rsp);
		
		if (sm!=null){
			logger.log(Level.FINE, "received (SM):\n"+HexString.bufferToHex(rapdu.getBytes()));
			rapdu = sm.unwrap(rapdu);
		}
		logger.log(Level.FINE, "received (PLAIN):\n"+HexString.bufferToHex(rapdu.getBytes()));
		
		return rapdu;		
	}

}
