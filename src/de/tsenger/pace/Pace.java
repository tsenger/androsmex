package de.tsenger.pace;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.Crypto;
import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.paceASN1objects.PaceInfo_bc;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.asn1.sec.SECNamedCurves;
import ext.org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import ext.org.bouncycastle.asn1.x9.X9ECParameters;
import ext.org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import ext.org.bouncycastle.math.ec.ECCurve;
import ext.org.bouncycastle.math.ec.ECPoint;
import ext.org.bouncycastle.math.ec.ECPoint.Fp;


public class Pace {
	
	private boolean debugging = false;
	private Logger logger = null;
	private ECPoint pointG = null;
	private ECPoint pointG_strich = null;
	private ECCurve.Fp curve = null;
	private byte[] derivatedPassword = null;
	private byte[] nonce_s = null;
	private VMPCRandomGenerator randomGenerator = new VMPCRandomGenerator();
	
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
		pointG = (Fp) cp.getG();
		curve = (ext.org.bouncycastle.math.ec.ECCurve.Fp) cp.getCurve();
	}
	
	public Pace(PaceInfo_bc pi) throws IOException {
		paceInfo = pi;
		initializeLogger();
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
	
	/** Aktiviert das Logging
	 * @param b "True" aktiviert das Logging, "False" deaktiviert es.
	 */
	public void debug(boolean b) {
		debugging = b;
	}
	
	/** Berechnet das erste KeyPair. x1: privater Schlüssel (Zufallszahl) und X1 = x1*G: öffentlicher Schlüsssel 
	 * @param password Das Password welches für PACE verwendet werden soll (CAN, PIN, PUK) als String
	 * @param z Die encrypted Nonce der Karte als Byte-Array
	 * @return Der erste öffentliche Schlüssel X1 des Terminals.
	 */
	public ECPoint getX1(String password, byte[] z) {
		derivatedPassword = Crypto.derivateAES128Key(password.getBytes(),new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03});
		nonce_s = Crypto.decryptAESblock(derivatedPassword, z);
		if (debugging) logger.log(Level.INFO, "nonce s:\n"+HexString.bufferToHex(nonce_s));
		if (debugging)
//			PCD_SK_x1 = new BigInteger("752287F5B02DE3C4BC3E17945118C51B23C97278E4CD748048AC56BA5BDC3D46",16);
			PCD_SK_x1 = new BigInteger("254685c0be3c20892cdb9ffa3ee0373bb76e6f2c0c38e0e86e639a463a2c3906",16);
		else {
			byte[] x1 = new byte[32];
			randomGenerator.nextBytes(x1);
			PCD_SK_x1 = new BigInteger(1, x1);
		}
		if (debugging) logger.log(Level.INFO, "Private Key PCD_SK_x1:\n"+PCD_SK_x1.toString(16));
		PCD_PK_X1 = pointG.multiply(PCD_SK_x1);
		if (debugging) logger.log(Level.INFO, "Public Key PCD_PK_X1:\n"+HexString.bufferToHex(PCD_PK_X1.getEncoded()));
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
		if (debugging) 
//			PCD_SK_x2 = new BigInteger("9D9A32DF93A57CCE33CA3CDD3457E33A976F293546C73550F397259C93BE0120",16);
			PCD_SK_x2 = new BigInteger("7ef042a3ba57381003221e876a236739397a4a99c9502a3c783c38c8b3f5a02f",16);
		else {
			byte[] x2 = new byte[32];
			randomGenerator.nextBytes(x2);
			PCD_SK_x2 = new BigInteger(1, x2);
		}
		if (debugging) logger.log(Level.INFO, "Private Key PCD_SK_x2:\n"+PCD_SK_x2.toString(16));
		PCD_PK_X2 = (Fp) pointG_strich.multiply(PCD_SK_x2);
		if (debugging) logger.log(Level.INFO, "Public Key PCD_PK_X2:\n"+HexString.bufferToHex(PCD_PK_X2.getEncoded()));
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
		if (debugging) logger.log(Level.INFO, "Shared Secret K:\n"+HexString.bufferToHex(SharedSecret_K));
		K_enc = Crypto.derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01});
		K_mac = Crypto.derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02});
		if (debugging) logger.log(Level.INFO, "K_enc:\n"+HexString.bufferToHex(K_enc));
		if (debugging) logger.log(Level.INFO, "K_mac:\n"+HexString.bufferToHex(K_mac));
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
		if (debugging) logger.log(Level.INFO, "Public Key PICC_PK_Y1:\n"+HexString.bufferToHex(PICC_PK_Y1.getEncoded())+
				"\nPCD_SK_x1:\n"+PCD_SK_x1.toString(16)+
				"\nSharedSecret_P = PCD_SK_x1 * PICC_PK_Y1:\n"+HexString.bufferToHex(SharedSecret_P.getEncoded()));
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
		pointG_strich = (Fp) g_temp.add(SharedSecret_P);
		if (debugging) logger.log(Level.INFO, "nonces:\n"+HexString.bufferToHex(ms.toByteArray())+"\nNew Point G':\n"+HexString.bufferToHex(pointG_strich.getEncoded()));
	}

	
	/**
	 * Erstellt einen Logger
	 * @throws IOException 
	 */
	private void initializeLogger() throws IOException {
		logger = Logger.getLogger(Pace.class.getName());
//	    FileHandler fh = null;
//	    fh = new FileHandler();
//	    logger.addHandler(fh);
	    logger.setLevel(Level.ALL);
//	    SimpleFormatter formatter = new SimpleFormatter();
//	    fh.setFormatter(formatter);
	}
	


}
