package de.tsenger.androsmex;

import java.io.IOException;

import de.tsenger.androsmex.tools.HexString;
import android.nfc.tech.IsoDep;

public class IsoDepCardHandler implements CardHandler {
	
	private IsoDep tag = null;
	
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

	public boolean isConnected() {
		return tag.isConnected();
	}

	public ResponseAPDU sendCommandAPDU(CommandAPDU cmd) throws Exception {
		byte[] rsp=null;
		if (tag==null) throw new Exception ("Tag is NULL!");
		if (!tag.isConnected()) tag.connect();
			try {
				rsp = tag.transceive(cmd.getBytes());
			} catch (IOException e) {
				throw new Exception("TRANSCEIVE FAILED at C-APDU: \n"+HexString.bufferToHex(cmd.getBytes())+"\nError-Message: "+e.getMessage());
			}
		return new ResponseAPDU(rsp);		
	}

}
