package de.tsenger.androsmex.pace;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.prng.VMPCRandomGenerator;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.Fp;

import de.tsenger.androsmex.pace.paceASN1objects.PaceInfo_bc;
import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.Crypto;


public class Pace {

	private ECPoint pointG = null;
	private ECPoint pointG_strich = null;
	private ECCurve.Fp curve = null;
	private byte[] derivatedPassword = null;
	private byte[] nonce_s = null;
	private final VMPCRandomGenerator randomGenerator = new VMPCRandomGenerator();
	
	private BigInteger PCD_SK_x1 = null;
	private ECPoint PCD_PK_X1 = null;
	
	private BigInteger PCD_SK_x2 = null;
	private ECPoint PCD_PK_X2 = null;
	
	private ECPoint PICC_PK_Y1 = null;
	private ECPoint PICC_PK_Y2 = null;
	
	private ECPoint.Fp SharedSecret_P = null;
	private byte[] SharedSecret_K = null;
	private byte[] K_enc = null;
	private byte[] K_mac = null;
	
	private PaceInfo_bc paceInfo = null;
	
	
	
	private void setPaceParameter(X9ECParameters cp) {
		pointG = cp.getG();
		curve = (org.spongycastle.math.ec.ECCurve.Fp) cp.getCurve();
	}
	
	public Pace(PaceInfo_bc pi) throws IOException {
		paceInfo = pi;
		X9ECParameters cp = null;
		switch (paceInfo.getParameterId()) {
		case 8: 
			cp = SECNamedCurves.getByName ("secp192r1");
			break;
		case 9: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp192r1");
			break;
		case 10: 
			cp = SECNamedCurves.getByName ("secp224r1");
			break;
		case 11: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp224r1");
			break;
		case 12: 
			cp = SECNamedCurves.getByName ("secp256r1");
			break;
		case 13: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp256r1");
			break;
		case 14: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp320r1");
			break;
		case 15: 
			cp = SECNamedCurves.getByName ("secp384r1");
			break;
		case 16: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp384r1");
			break;
		case 17: 
			cp = TeleTrusTNamedCurves.getByName ("brainpoolp512r1");
			break;
		case 18: 
			cp = SECNamedCurves.getByName ("secp521r1");
			break;
		}
		setPaceParameter(cp);
		
		Random rnd = new Random();
		randomGenerator.addSeedMaterial(rnd.nextLong());
	
	}
	
	/** Berechnet das erste KeyPair. x1: privater Schlüssel (Zufallszahl) und X1 = x1*G: öffentlicher Schlüsssel 
	 * @param password Das Password welches für PACE verwendet werden soll (CAN, PIN, PUK) als String
	 * @param z Die encrypted Nonce der Karte als Byte-Array
	 * @return Der erste öffentliche Schlüssel X1 des Terminals.
	 */
	public ECPoint getX1(String password, byte[] z) {
		derivatedPassword = Crypto.derivateAES128Key(password.getBytes(),new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03});
		nonce_s = Crypto.decryptAESblock(derivatedPassword, z);
		byte[] x1 = new byte[32];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
		PCD_PK_X1 = pointG.multiply(PCD_SK_x1);	
		return PCD_PK_X1;		
	}
	
	/** Berechnet mit Hilfe des öffentlichen Schlüssels der Karte das erste Shared Secret P,
	 *  den neuen Punkt G', sowie den zweiten öffentlichen Schlüssels des Terminals (X2 = x2 * G').
	 * @param Y1 Erster öffentlicher Schlüssel der Karte
	 * @return Zweiter öffentlicher Schlüssel X2 des Terminals.
	 * @throws Exception
	 */
	public ECPoint getX2(ECPoint.Fp Y1) throws Exception {
		PICC_PK_Y1 = Y1;
		calculateSharedSecretP(); //berechnet P
		calculateNewPointG(); //berechnet G'
		byte[] x2 = new byte[32];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
		PCD_PK_X2 = pointG_strich.multiply(PCD_SK_x2);
		return PCD_PK_X2;
	}
	
	public ECPoint getX2(byte[] Y1Bytes) throws Exception {
		return getX2((Fp) Converter.byteArrayToECPoint(Y1Bytes, curve));
	}
	
	/** Erzeugt das finale Shared Secret K
	 * @param Y2 Zweiter öffentlicher Schlüssel Y2 der Karte
	 * @return Shared Secret K
	 */
	public byte[] getK(ECPoint.Fp Y2) {
		PICC_PK_Y2 = Y2;
		ECPoint.Fp  K = (Fp) PICC_PK_Y2.multiply(PCD_SK_x2);
		SharedSecret_K =  Converter.bigIntToByteArray(K.getX().toBigInteger());
		K_enc = Crypto.derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01});
		K_mac = Crypto.derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02});
		return SharedSecret_K;
	}
	
	public byte[] getK(byte[] Y2Bytes) throws Exception {
		return getK((Fp) Converter.byteArrayToECPoint(Y2Bytes, curve));
	}
	
	public byte[] getKenc() {
		return K_enc;
	}
	
	public byte[] getKmac() {
		return K_mac;
	}
	
	public ECCurve.Fp getCurve() {
		return curve;
	}
	
	
	/** Erzeugt aus dem Public Key 1 der Karte (PICC_PK_Y1) und dem Secret Key PCD_SK_x1 das erste Shared Secret P
	 * @throws Exception Falls PICC_PK_Y1 noch nicht gesetzt wurde (während getX2) wird diese Exception geworfen.
	 * 
	 */
	private void calculateSharedSecretP() throws Exception {
		if (PICC_PK_Y1==null) throw new Exception("PICC_PK_Y1 not initialized!");
		SharedSecret_P = (Fp) PICC_PK_Y1.multiply(PCD_SK_x1);
	}

	
	/**
	 * Erzeugt aus der nonce s, dem Punkt G und dem shared secret P den neuen Punkt G' 
	 * G' = s*G+P
	 * @throws Exception Falls nonce s noch nicht berechnet wurde (passiert während getX1) wird diese Exception geworfen
	 */
	private void calculateNewPointG() throws Exception {
		if (nonce_s==null) throw new Exception("nonce s not initialized!");
		BigInteger ms = new BigInteger(1, nonce_s);
		ECPoint g_temp = pointG.multiply(ms);
		pointG_strich = g_temp.add(SharedSecret_P);
	}


}
