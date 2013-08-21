package de.tsenger.androsmex.pace;

import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_3DES_CBC_CBC;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_128;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_192;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_256;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_3DES_CBC_CBC;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_128;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_192;
import static de.tsenger.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_256;
import static de.tsenger.androsmex.pace.DHStandardizedDomainParameters.modp1024_160;
import static de.tsenger.androsmex.pace.DHStandardizedDomainParameters.modp2048_224;
import static de.tsenger.androsmex.pace.DHStandardizedDomainParameters.modp2048_256;

import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.support.v4.content.LocalBroadcastManager;
import de.tsenger.androsmex.IsoDepCardHandler;
import de.tsenger.androsmex.asn1.AmDHPublicKey;
import de.tsenger.androsmex.asn1.AmECPublicKey;
import de.tsenger.androsmex.asn1.BSIObjectIdentifiers;
import de.tsenger.androsmex.asn1.DomainParameter;
import de.tsenger.androsmex.asn1.DynamicAuthenticationData;
import de.tsenger.androsmex.asn1.PaceDomainParameterInfo;
import de.tsenger.androsmex.asn1.PaceInfo;
import de.tsenger.androsmex.crypto.AmAESCrypto;
import de.tsenger.androsmex.crypto.AmCryptoProvider;
import de.tsenger.androsmex.crypto.AmDESCrypto;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.MSESetAT;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.HexString;

public class PaceOperator extends AsyncTask<Void, String, String> {

	private final IsoDepCardHandler card;
	private Logger logger;
	private int passwordRef = 0;
	private int terminalType = 0;
	private byte[] passwordBytes;
	private String protocolOIDString;
	private DHParameters dhParameters = null;
	private X9ECParameters ecdhParameters = null;
	private Pace pace = null;
	private int keyLength = 0;
	private AmCryptoProvider crypto = null;
	private SecureMessaging sm;

	private DomainParameter dp = null;
	
	private Context context;
	
	long starttime = 0;
	long endtime = 0;
	

	public PaceOperator(IsoDepCardHandler card, Context context) {
		this.card = card;
		this.context = context;
	}

	public void setAuthTemplate(PaceInfo pi, String password, Logger logger, SharedPreferences prefs) {

		dp = new DomainParameter(pi.getParameterId());
		this.logger = logger;
		passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));

		protocolOIDString = pi.getProtocolOID();

		if (passwordRef == 1) passwordBytes = calcSHA1(password.getBytes());
		else passwordBytes = password.getBytes();

		getStandardizedDomainParameters(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString()) || protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString()) || protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}

	public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi,
			String password, Logger logger, SharedPreferences prefs)
			throws Exception {

		this.logger = logger;
		protocolOIDString = pi.getProtocolOID();
		passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));

		if (pi.getParameterId() >= 0 && pi.getParameterId() <= 31)
			throw new Exception("ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new Exception("PaceInfo doesn't match the PaceDomainParameterInfo");

		if (passwordRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getProprietaryDomainParameters(pdpi);

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}

	public void performPACE() throws IOException, SecureMessagingException, PaceException {

		// send MSE:SetAT
		logger.log(Level.FINE, "Send MSE:Set AT command");
		int resp = sendMSESetAT(terminalType).getSW();
		if (resp != 0x9000)
			logger.log(Level.FINE, "MSE:Set AT failed. SW: " + Integer.toHexString(resp));

		// send first GA and get nonce
		logger.log(Level.FINE, "1. General Authentication (get nonce) command");
		byte[] nonce_z = getNonce().getDataObject(0);
//		logger.log(Level.FINE, "encrypted nonce z:\n" + HexString.bufferToHex(nonce_z));
		byte[] nonce_s = decryptNonce(nonce_z);
//		logger.log(Level.FINE, "decrypted nonce s:\n" + HexString.bufferToHex(nonce_s));
		byte[] X1 = pace.getX1(nonce_s);

		// X1 zur Karte schicken und Y1 empfangen
		logger.log(Level.FINE, "2. General Authentication (map nonce) command");
		byte[] Y1 = mapNonce(X1).getDataObject(2);;

		byte[] X2 = pace.getX2(Y1);
		// X2 zur Karte schicken und Y2 empfangen.
		logger.log(Level.FINE, "3. General Authentication (key agreement) command");
		byte[] Y2 = performKeyAgreement(X2).getDataObject(4);

		byte[] S = pace.getSharedSecret_K(Y2); 
		byte[] kenc = getKenc(S);
		byte[] kmac = getKmac(S);
//		logger.log(Level.FINE, "Shared Secret K: " + HexString.bufferToHex(S) + "\nkenc: " + HexString.bufferToHex(kenc) + "\nkmac: "
//				+ HexString.bufferToHex(kmac));

		// Authentication Token T_PCD berechnen
		byte[] tpcd = calcAuthToken(kmac, Y2);

		// Authentication Token zur Karte schicken
		logger.log(Level.FINE, "4. General Authentication (mutual authentication) command");
		byte[] tpicc = performMutualAuthentication(tpcd).getDataObject(6);

		// Authentication Token T_PICC berechnen
		byte[] tpicc_strich = calcAuthToken(kmac, X2);

		// Prüfe ob tpicc = t'picc=MAC(kmac,X2)
		if (!Arrays.areEqual(tpicc, tpicc_strich)) {
			logger.log(Level.FINE, "Mutual Authentication failed! Tokens are different");
			throw new PaceException("Mutual Authentication failed! Tokens are different");
		}

		sm = new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);

		card.setSecureMessaging(sm);

	}

	/**
	 * Der Authentication Token berechnet sich aus dem MAC (mit Schlüssel kmac)
	 * über einen AmPublicKey welcher den Object Identifier des verwendeten
	 * Protokolls und den von der empfangenen ephemeralen Public Key (Y2)
	 * enthält. Siehe dazu TR-03110 V2.05 Kapitel A.2.4 und D.3.4 Hinweis: In
	 * älteren Versionen des PACE-Protokolls wurden weitere Parameter zur
	 * Berechnung des Authentication Token herangezogen.
	 * 
	 * @param data
	 *            Byte-Array welches ein DO84 (Ephemeral Public Key) enthält
	 * @param kmac
	 *            Schlüssel K_mac für die Berechnung des MAC
	 * @return Authentication Token
	 */
	private byte[] calcAuthToken(byte[] kmac, byte[] data) {
		byte[] tpcd = null;
		if (pace instanceof PaceECDH) {
			Fp curve = (Fp) dp.getECParameter().getCurve();
			ECPoint pointY = Converter.byteArrayToECPoint(data, curve);
			AmECPublicKey pkpcd = new AmECPublicKey(protocolOIDString, pointY);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		} else if (pace instanceof PaceDH) {
			BigInteger y = new BigInteger(data);
			AmDHPublicKey pkpcd = new AmDHPublicKey(protocolOIDString, y);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		return tpcd;
	}

	/**
	 * Send a plain General Authentication Command to get a encrypted nonce from
	 * the card.
	 * 
	 * @return
	 * @throws IOException
	 * @throws PaceException
	 * @throws SecureMessagingException
	 * @throws Exception
	 */
	private DynamicAuthenticationData getNonce() throws SecureMessagingException, PaceException, IOException {
		byte[] data = new byte[] { 0x7C, 0x00 };
		return sendGeneralAuthenticate(true, data);
	}

	private DynamicAuthenticationData sendGeneralAuthenticate(boolean chaining, byte[] data) throws SecureMessagingException, PaceException, IOException {

		CommandAPDU capdu = new CommandAPDU(chaining ? 0x10 : 0x00, 0x86, 0x00, 0x00, data, 0xff);

		ResponseAPDU resp = card.transceive(capdu);

		if (resp.getSW() != 0x9000)
			throw new PaceException("General Authentication returns: "	+ HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
		return dad;
	}

	private DynamicAuthenticationData mapNonce(byte[] mappingData)
			throws SecureMessagingException, PaceException, IOException {

		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
		dad81.addDataObject(1, mappingData);

		return sendGeneralAuthenticate(true, dad81.getDEREncoded());
	}

	private DynamicAuthenticationData performMutualAuthentication(
			byte[] authToken) throws SecureMessagingException, PaceException,
			IOException {

		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		dad85.addDataObject(5, authToken);

		return sendGeneralAuthenticate(false, dad85.getDEREncoded());
	}

	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK)
			throws PaceException, SecureMessagingException, IOException {

		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
		dad83.addDataObject(3, ephemeralPK);

		return sendGeneralAuthenticate(true, dad83.getDEREncoded());
	}

	private byte[] decryptNonce(byte[] z) {
		byte[] derivatedPassword = null;
		derivatedPassword = getKey(keyLength, passwordBytes, 3);
		return crypto.decryptBlock(derivatedPassword, z);
	}

	private byte[] getKenc(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 1);
	}

	private byte[] getKmac(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 2);
	}

	private ResponseAPDU sendMSESetAT(int terminalType) throws IOException, SecureMessagingException {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_PACE);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(passwordRef);
		switch (terminalType) {
		case 0:
			break;
		case 1:
			mse.setISChat();
			break;
		case 2:
			mse.setATChat();
			break;
		case 3:
			mse.setSTChat();
			break;
		default:
			throw new IllegalArgumentException("Unknown Terminal Reference: "
					+ terminalType);
		}
		return card.transceive(mse.getCommandAPDU());
	}

	private void getStandardizedDomainParameters(int parameterId) {

		switch (parameterId) {
		case 0:
			dhParameters = modp1024_160();
			break;
		case 1:
			dhParameters = modp2048_224();
			break;
		case 3:
			dhParameters = modp2048_256();
			break;
		case 8:
			ecdhParameters = SECNamedCurves.getByName("secp192r1");
			break;
		case 9:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp192r1");
			break;
		case 10:
			ecdhParameters = SECNamedCurves.getByName("secp224r1");
			break;
		case 11:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp224r1");
			break;
		case 12:
			ecdhParameters = SECNamedCurves.getByName("secp256r1");
			break;
		case 13:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
			break;
		case 14:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp320r1");
			break;
		case 15:
			ecdhParameters = SECNamedCurves.getByName("secp384r1");
			break;
		case 16:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp384r1");
			break;
		case 17:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp512r1");
			break;
		case 18:
			ecdhParameters = SECNamedCurves.getByName("secp521r1");
			break;
		}
	}

	private byte[] getKey(int keyLength, byte[] K, int c)  {

		byte[] key = null;

		KeyDerivationFunction kdf = new KeyDerivationFunction(K, c);

		switch (keyLength) {
		case 112:
			key = kdf.getDESedeKey();
			break;
		case 128:
			key = kdf.getAES128Key();
			break;
		case 192:
			key = kdf.getAES192Key();
			break;
		case 256:
			key = kdf.getAES256Key();
			break;
		}
		return key;
	}

	// TODO Funktioniert momentan nur mit EC
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi)	throws PaceException {
		if (pdpi.getDomainParameter().getAlgorithm().toString()
				.contains(BSIObjectIdentifiers.id_ecc.toString())) {
			ASN1Sequence seq = (ASN1Sequence) pdpi.getDomainParameter()
					.getParameters().getDERObject().toASN1Object();
			ecdhParameters = new X9ECParameters(seq);
		} else
			throw new PaceException(
					"Can't decode properietary domain parameters in PaceDomainParameterInfo!");
	}

	/**
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge
	 * für PACE
	 */
	private void getCryptoInformation(PaceInfo pi) {
		String protocolOIDString = pi.getProtocolOID();
		if (protocolOIDString.equals(id_PACE_DH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_3DES_CBC_CBC
						.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_128
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128
						.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192
						.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256
						.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

	/**
	 * Berechnet den SHA1-Wert des übergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom übergebenen Byte-Array
	 */
	private byte[] calcSHA1(byte[] input) {
		byte[] md = new byte[20];
		SHA1Digest sha1 = new SHA1Digest();
		sha1.update(input, 0, input.length);
		sha1.doFinal(md, 0);
		return md;
	}

	public SecureMessaging getSMObject() {
		return sm;
	}

	@Override
	protected String doInBackground(Void... params) {
				
		try {
			starttime = System.currentTimeMillis();
			performPACE();
			
		} catch (IOException e) {
			logger.log(Level.FINE, e.getMessage());
			return "PACE failed!";
		} catch (SecureMessagingException e) {
			logger.log(Level.FINE, e.getMessage());
			return "PACE failed!";
		} catch (PaceException e) {
			logger.log(Level.FINE, e.getMessage());
			return "PACE failed!";
		} finally {
			endtime = System.currentTimeMillis();
		}
		
		return "PACE established!";
	}

	@Override
	protected void onProgressUpdate(String... strings) {
		if (strings != null) {
			logger.log(Level.INFO, strings[0]);
		}
	}

	@Override
	protected void onPostExecute(String result) {
				
		Intent intent = new Intent("pace_finished");
		intent.putExtra("message", result+"\nTime used: " + (endtime - starttime) + " ms");
		LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
	}

}
