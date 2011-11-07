package de.tsenger.androsmex.pace;


import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.math.ec.ECPoint;

import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.widget.TextView;
import de.tsenger.androsmex.CardCommands;
import de.tsenger.androsmex.CardHandler;
import de.tsenger.androsmex.CommandAPDU;
import de.tsenger.androsmex.ResponseAPDU;
import de.tsenger.androsmex.pace.paceASN1objects.AuthenticationToken;
import de.tsenger.androsmex.pace.paceASN1objects.DynamicAuthenticationData;
import de.tsenger.androsmex.pace.paceASN1objects.PaceInfo_bc;
import de.tsenger.androsmex.pace.paceASN1objects.SecurityInfos_bc;
import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.HexString;


public class PACETag extends AsyncTask<Void, String, String>{

	private final CardHandler card;
	private final String password;
	private final TextView txtview;
	private int pwRef = 0;
	private int terminalRef = 0;

	public PACETag(CardHandler card, String password, TextView txtview, SharedPreferences prefs) {
		this.card = card;
		this.password = password;
		this.txtview = txtview;
		pwRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		terminalRef = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));
	}

	
	public byte[] performPACE() throws Exception {
		publishProgress("Read EF.CardAccess...\n");
		SecurityInfos_bc efca = getEFCardAccess();
		
		PaceInfo_bc paceInfo = efca.getPACEInfo();
		DERObjectIdentifier protocol = paceInfo.getProtocol();
		publishProgress("PACEInfo Protocol:\n"+protocol.toString());
		
		byte[] response = MSESetAT(protocol).sw();
		publishProgress("MSE:SetAT response: \n"+HexString.bufferToHex(response));
		
		byte[] nonce_z = getNonce();
		if (nonce_z==null) throw new Exception("nonce_z ist NULL!");
		publishProgress("encrypted nonce z: \n"+HexString.bufferToHex(nonce_z));
		
		//General Authentication Step 2
		Pace pace = new Pace(paceInfo);
		ECPoint X1 = pace.getX1(password, nonce_z);
		byte[] X1Bytes = X1.getEncoded();
		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
		dad81.setMappingData81(X1Bytes);
		byte[] dad81Bytes = dad81.getDEREncoded();
		CommandAPDU capdu1 = new CommandAPDU(255);
		capdu1.append(HexString.hexToBuffer("10860000"));
		capdu1.append((byte)dad81Bytes.length);
		capdu1.append(dad81Bytes);
		capdu1.append((byte)0);
		publishProgress("send mapping data CAPDU: \n"+HexString.bufferToHex(capdu1.getBytes()));
		ResponseAPDU resp1 = null;
		resp1  = card.sendCommandAPDU(capdu1);
		publishProgress("receive mapping data RAPDU: \n"+HexString.bufferToHex(resp1.getBytes()));
		if (resp1.data()==null) throw new Exception("Response = null");
		
		//General Authentication Step 3
		DynamicAuthenticationData dad82 = new DynamicAuthenticationData();
		if (resp1.data()==null) throw new Exception ("resp1 returns no data!");
		dad82.decode(resp1.data());
		ECPoint X2 = pace.getX2(dad82.getMappingData82());
		byte[] X2Bytes = X2.getEncoded();
		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
		dad83.setEphemeralPK83(X2Bytes);
		byte[] dad83Bytes = dad83.getDEREncoded();
		CommandAPDU capdu2 = new CommandAPDU(255);
		capdu2.append(HexString.hexToBuffer("10860000"));
		capdu2.append((byte)dad83Bytes.length);
		capdu2.append(dad83Bytes);
		capdu2.append((byte)0);
		publishProgress("send terminal ephemeral public key CAPDU: \n"+HexString.bufferToHex(capdu2.getBytes()));
		ResponseAPDU resp2 = null;
		resp2  = card.sendCommandAPDU(capdu2);
		publishProgress("receive chip ephemeral public key RAPDU: \n"+HexString.bufferToHex(resp2.getBytes()));
		
		DynamicAuthenticationData dad84 = new DynamicAuthenticationData();
		if(resp2.data()==null) throw new Exception ("resp2 returns no data!");
		dad84.decode(resp2.data());
		byte[] K = pace.getK(dad84.getEphemeralPK84());
		publishProgress("Shared Secret K: \n"+HexString.bufferToHex(K));
		publishProgress("Kmac: \n"+HexString.bufferToHex(pace.getKmac()));
		publishProgress("Kenc: \n"+HexString.bufferToHex(pace.getKenc()));
		
//		protocol = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
		AuthenticationToken at = new AuthenticationToken(protocol, Converter.byteArrayToECPoint(dad84.getEphemeralPK84(), pace.getCurve()));
		
		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		dad85.setAuthenticationToken85(at.getToken(pace.getKmac()));
		byte[] dad85Bytes = dad85.getDEREncoded();
		
		CommandAPDU capdu3 = new CommandAPDU(255);
		capdu3.append(HexString.hexToBuffer("00860000"));
		capdu3.append((byte)dad85Bytes.length);
		capdu3.append(dad85Bytes);
		capdu3.append((byte)0);
		publishProgress("send terminal authentication token: \n"+HexString.bufferToHex(capdu3.getBytes()));
		ResponseAPDU resp3 = null;
		resp3  = card.sendCommandAPDU(capdu3);
		publishProgress("receive chip authentication token : \n"+HexString.bufferToHex(resp3.getBytes()));
		
		if (resp3.sw1()==(byte)0x90) {
			publishProgress("\n-=PACE established!=-");
		}
		
	
		return resp3.sw();
	}
	
	public void elCommand() {
		byte[]cmd=HexString.hexToBuffer("002a00be0001337f4e82012e" +
				"a05f290100420f44454456544944" +
				"42534944453030337f494f060a04007f" +
				"00070202020203864104524b1a697388" +
				"11acd363b046de5153c58f8485b91794" +
				"31e9bf4e595e6f69e4751e7fe18e54c4" +
				"c87117551960291405827ec0d57640b9" +
				"9e5b8be8ec6e51b4357b5f200f444541" +
				"5454494442534944453030337f4c1206" +
				"0904007f00070301020253053c0f01fb" +
				"305f25060101000202045f2406010100" +
				"0502045f37403951c482e89205504999" +
				"8d9cd143447e7af8626f7c060b26ded9" +
				"1273c6e558336187282f042a0b834bad" +
				"7287bd1917a7d4b12c2e238dce4ff2e9" +
				"feab57be8957524b1a69738811acd363" +
				"b046de5153c58f8485b9179431e9bf4e" +
				"595e6f69e4751e7fe18e54c4c8711755" +
				"1960291405827ec0d57640b99e5b8be8" +
				"ec6e51b4357b5f200f44454100000000");
		CommandAPDU testcmd = new CommandAPDU(555);
		
		ResponseAPDU resp = null;
		testcmd.append(cmd);
		try {
			resp  = card.sendCommandAPDU(testcmd);
		} catch (Exception e) {
			publishProgress("EXCEPTION!\n"+e.getMessage());
		}
		publishProgress("CAPDU length: "+cmd.length+"\nResponse: "+HexString.bufferToHex(resp.getBytes())+"\n");
		
	}

	public SecurityInfos_bc getEFCardAccess() throws Exception {
		SecurityInfos_bc efCardAccess = new SecurityInfos_bc();
		CardCommands cc = new CardCommands(card, null);
		efCardAccess.decode(cc.getFile((byte)0x1C));
		return efCardAccess;
	}
	
	public void setPasswordRef(int ref) {
		pwRef = ref;
	}

	private byte[] getNonce() throws Exception {
		CommandAPDU capdu = new CommandAPDU(8);
		capdu.append(HexString.hexToBuffer("10860000027C0000"));
		ResponseAPDU resp = card.sendCommandAPDU(capdu);
		if (resp.data()==null) throw new Exception("Get nonce returns: "+HexString.bufferToHex(resp.getBytes()));
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.data());
		return dad.getEncryptedNonce80();
	}

	private ResponseAPDU MSESetAT(DERObjectIdentifier protocol) throws Exception {
		MSECommand mse = new MSECommand(200);
		mse.setAT(MSECommand.setAT_PACE);
		mse.setCMR(protocol);
		mse.setKeyReference(pwRef);
		switch (terminalRef) {
		case 0: break;
		case 1: mse.setISChat(); break;
		case 2: mse.setATChat(); break;
		case 3: mse.setSTChat(); break;
		}
		ResponseAPDU resp = card.sendCommandAPDU(mse);
		return resp;
	}

	@Override
	protected String doInBackground(Void... params) {
		long starttime = System.currentTimeMillis();
		try {
			performPACE();
		} catch (Exception e) {
			return e.getMessage();
		}
		long endtime = System.currentTimeMillis();
		publishProgress("Time used: "+(endtime-starttime)+" ms\n");
		return null;
	}
	
	@Override
	protected void onProgressUpdate(String...strings) {
		if (strings!=null) {
			txtview.append(strings[0]+"\n");
		}
	}
	
	@Override
	protected void onPostExecute(String string) {
		if (string!=null) txtview.append(string);
	}

}
