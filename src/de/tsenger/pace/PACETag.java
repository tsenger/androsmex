package de.tsenger.pace;


import android.os.AsyncTask;
import android.widget.TextView;
import de.tsenger.androsmex.CardCommands;
import de.tsenger.androsmex.CardHandler;
import de.tsenger.androsmex.CommandAPDU;
import de.tsenger.androsmex.ResponseAPDU;
import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.paceASN1objects.AuthenticationToken;
import de.tsenger.pace.paceASN1objects.CertificateHolderAuthorizationTemplate;
import de.tsenger.pace.paceASN1objects.DynamicAuthenticationData;
import de.tsenger.pace.paceASN1objects.PaceInfo_bc;
import de.tsenger.pace.paceASN1objects.SecurityInfos;
import de.tsenger.pace.paceASN1objects.SecurityInfos_bc;
import ext.org.bouncycastle.asn1.ASN1Integer;
import ext.org.bouncycastle.asn1.ASN1Sequence;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.math.ec.ECPoint;

public class PACETag extends AsyncTask<Void, String, String>{

	private CardHandler card;
	private String password;
	private TextView txtview;
	private int pwRef = MSECommand.KeyReference_CAN;

	public PACETag(CardHandler card, String password, TextView txtview) {
		this.card = card;
		this.password = password;
		this.txtview = txtview;
	}

	
	public byte[] performPACE() throws Exception {
		publishProgress("\nRead EF.CardAccess...\n");
		SecurityInfos_bc efca = getEFCardAccess();
		
		PaceInfo_bc paceInfo = efca.getPACEInfo();
		DERObjectIdentifier protocol = paceInfo.getProtocol();
		publishProgress("PACEInfo Protocol:\n"+protocol.toString()+"\n");
		
		byte[] response = MSESetAT(protocol).sw();
		publishProgress("MSE:SetAT response: "+HexString.bufferToHex(response)+"\n");
		
		byte[] nonce_z = getNonce();
		if (nonce_z==null) throw new Exception("nonce_z ist NULL!");
		publishProgress("Nonce Z: \n"+HexString.bufferToHex(nonce_z)+"\n");
		
		//General Authentication Step 2
		Pace pace = new Pace(paceInfo);
		pace.debug(false);
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
//		publishProgress("GA Step 2 command: \n"+HexString.bufferToHex(capdu1.getBytes())+"\n");
		ResponseAPDU resp1 = null;
		resp1  = card.sendCommandAPDU(capdu1);
//		publishProgress("GA Step 2 response: \n"+HexString.bufferToHex(resp1.getBytes())+"\n");
		if (resp1.data()==null) throw new Exception("Response = null");
		
		//General Authentication Step 3
		DynamicAuthenticationData dad82 = new DynamicAuthenticationData();
		if (resp1.data()==null) throw new Exception ("resp1 returns no data!");
		dad82.decode(resp1.data());
//		publishProgress("MappingData82: \n"+HexString.bufferToHex(dad82.getMappingData82())+"\n");
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
//		publishProgress("GA Step 3 command: "+HexString.bufferToHex(capdu2.getBytes())+"\n");
		ResponseAPDU resp2 = null;
		resp2  = card.sendCommandAPDU(capdu2);
//		publishProgress("GA Step 3 response: "+HexString.bufferToHex(resp2.getBytes())+"\n");
		
		DynamicAuthenticationData dad84 = new DynamicAuthenticationData();
		if(resp2.data()==null) throw new Exception ("resp2 returns no data!");
		dad84.decode(resp2.data());
//		publishProgress("EphemerakPK84: \n"+HexString.bufferToHex(dad84.getEphemeralPK84())+"\n");
		byte[] K = pace.getK(dad84.getEphemeralPK84());
		publishProgress("Shared Secret K: \n"+HexString.bufferToHex(K)+"\n");
		publishProgress("Kmac: \n"+HexString.bufferToHex(pace.getKmac())+"\n");
		publishProgress("Kenc: \n"+HexString.bufferToHex(pace.getKenc())+"\n");
		
		protocol = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
		AuthenticationToken at = new AuthenticationToken(protocol, Converter.byteArrayToECPoint(dad84.getEphemeralPK84(), pace.getCurve()));
//		publishProgress("TokenInput:\n"+"Protocol: "+protocol.toString()+"\nPoint:" +HexString.bufferToHex(Converter.byteArrayToECPoint(dad84.getEphemeralPK84(), pace.getCurve()).getEncoded()));
		publishProgress("PCD Token:\n"+HexString.bufferToHex(at.getToken(pace.getKmac()))+"\n");
		
		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		dad85.setAuthenticationToken85(at.getToken(pace.getKmac()));
		byte[] dad85Bytes = dad85.getDEREncoded();
		
		CommandAPDU capdu3 = new CommandAPDU(255);
		capdu3.append(HexString.hexToBuffer("00860000"));
		capdu3.append((byte)dad85Bytes.length);
		capdu3.append(dad85Bytes);
		capdu3.append((byte)0);
//		publishProgress("GA Step 4 command: "+HexString.bufferToHex(capdu3.getBytes())+"\n");
		ResponseAPDU resp3 = null;
		resp3  = card.sendCommandAPDU(capdu3);
		publishProgress("GA Step 4 response: \n"+HexString.bufferToHex(resp3.getBytes())+"\n");
		
		if (resp3.sw1()==(byte)0x90) {
//			txtview.setBackgroundColor(Color.GREEN);
			publishProgress("\n-=PACE established!=-");
		}
		
	
		return resp3.sw();
	}
	
	public void elCommand() throws Exception {
		byte[]cmd=HexString.hexToBuffer("002a00bee77f4e81a05f290100420f44"+
				"45445654494442534944453030337f49"+
				"4f060a04007f00070202020203864104"+
				"524b1a69738811acd363b046de5153c5"+
				"8f8485b9179431e9bf4e595e6f69e475"+
				"1e7fe18e54c4c8711755196029140582"+
				"7ec0d57640b99e5b8be8ec6e51b4357b"+
				"5f200f44454154544944425349444530"+
				"30337f4c12060904007f000703010202"+
				"53053c0f01fb305f2506010100020204"+
				"5f24060101000502045f37403951c482"+
				"e892055049998d9cd143447e7af8626f"+
				"7c060b26ded91273c6e558336187282f"+
				"042a0b834bad7287bd1917a7d4b12c2e"+
				"238dce4ff2e9feab57be8957"+
				"524b1a69738811acd363b046de5153c5"+
				"8f8485b9179431e9bf4e595e6f69e475"+
				"1e7fe18e54c4c8711755196029140582"+
				"7ec0d57640b99e5b8be8ec6e51b4357b"+
				"5f200f44454154544944425349444530"+
				"30337f4c12060904007f000703010202"+
				"53053c0f01fb305f2506010100020204"+
				"5f24060101000502045f37403951c482"+
				"e892055049998d9cd143447e7af8626f"+
				"7c060b26ded91273c6e558336187282f"+
				"042a0b834bad7287bd1917a7d4b12c2e");
		CommandAPDU testcmd = new CommandAPDU(555);
		testcmd.append(cmd);
		ResponseAPDU resp3 = null;
		resp3  = card.sendCommandAPDU(testcmd);
		publishProgress(HexString.bufferToHex(resp3.getBytes()));
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
//		mse.setCMR(PACEOID.id_PACE_ECDH_GM_AES_CBC_CMAC_128);
		mse.setKeyReference(pwRef);
		// mse.setPrivateKeyReference((byte)0x0D);
		//mse.setCHAT(getChat());
		ResponseAPDU resp = card.sendCommandAPDU(mse);
		return resp;
	}

	private CertificateHolderAuthorizationTemplate getChat() {
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(PACEOID.id_AT);
		chat.setAuthorization(new byte[] { (byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xF7 });
		return chat;
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
			txtview.append(strings[0]);
		}
	}
	
	@Override
	protected void onPostExecute(String string) {
		if (string!=null) txtview.append(string);
	}

}
