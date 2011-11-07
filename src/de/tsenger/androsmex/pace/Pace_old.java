package de.tsenger.androsmex.pace;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import ext.org.bouncycastle.asn1.ASN1InputStream;
import ext.org.bouncycastle.asn1.DEROctetString;
import ext.org.bouncycastle.crypto.BlockCipher;
import ext.org.bouncycastle.crypto.engines.AESFastEngine;
import ext.org.bouncycastle.crypto.params.KeyParameter;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.ellipticcurves.ScalarMult;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.common.util.DefaultPRNG;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGFP;
import de.tsenger.androsmex.tools.HexString;

public class Pace_old {
	
	private boolean debugging = false;
	
	byte[] derivatedPassword = null;
	
	private byte[] nonce_s = null;
	private PointGFP pointG = null;
	private PointGFP pointG_strich = null;
	
	private FlexiBigInt orderp = null;
	private EllipticCurve curve = null;

	private Logger logger = null;
	
	private FlexiBigInt PCD_SK_x1 = null;
	private PointGFP PCD_PK_X1 = null;
	
	private PointGFP PICC_PK_Y1 = null;
	private PointGFP SharedSecret_P = null;
	
	private FlexiBigInt PCD_SK_x2 = null;
	private PointGFP PCD_PK_X2 = null;
	
	private PointGFP PICC_PK_Y2 = null;
	
	private byte[] SharedSecret_K = null;
	private byte[] K_enc = null;
	private byte[] K_mac = null;
	
	private DefaultPRNG randomGenerator = new DefaultPRNG();
	
	public Pace_old(CurveParamsGFP curveParameters) throws IOException {
		initializeLogger();
		pointG = (PointGFP) curveParameters.getG();
		curve = curveParameters.getE();
		orderp = curveParameters.getE().getQ();
	}
	
	public Pace_old(PointGFP G) throws IOException {
		initializeLogger();
		pointG = G;
	}
	
	/** Aktiviert das Logging
	 * @param b True aktiviert das Logging, False deaktiviert es.
	 */
	public void debug(boolean b) {
		debugging = b;
	}
	
	/** Berechnet das erste KeyPair. x1: privater Schlüssel (Zufallszahl) und X1 = x1*G: öffentlicher Schlüsssel 
	 * @param password Das Password welches für PACE verwendet werden soll (CAN, PIN, PUK) als String
	 * @param z Die encrypted Nonce der Karte als Byte-Array
	 * @return Der erste öffentliche Schlüssel X1 des Terminals.
	 */
	public PointGFP getX1(String password, byte[] z) {
		derivatedPassword = derivateAES128Key(password.getBytes(),new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03});
		nonce_s = decryptAESblock(derivatedPassword, z);
		if (debugging) logger.log(Level.INFO, "nonce s:\n"+HexString.bufferToHex(nonce_s));
		PCD_SK_x1 = new FlexiBigInt("752287F5B02DE3C4BC3E17945118C51B23C97278E4CD748048AC56BA5BDC3D46",16);
//		PCD_SK_x1 = new FlexiBigInt(256, randomGenerator);
		if (debugging) logger.log(Level.INFO, "Private Key PCD_SK_x1:\n"+PCD_SK_x1.toString(16));
		
		PCD_PK_X1 = (PointGFP) ScalarMult.multiply4(PCD_SK_x1, pointG);
		if (debugging) logger.log(Level.INFO, "Public Key PCD_PK_X1:\n"+PCD_PK_X1.toString());
		return PCD_PK_X1;		
	}
	
	/** Berechnet mit Hilfe des öffentlichen Schlüssels der Karte das erste Shared Secret P,
	 *  den neuen Punkt G', sowie den zweiten öffentlichen Schlüssels des Terminals (X2 = x2 * G').
	 * @param Y1 Erster öffentlicher Schlüssel der Karte
	 * @return Zweiter öffentlicher Schlüssel X2 des Terminals.
	 * @throws Exception
	 */
	public PointGFP getX2(PointGFP Y1) throws Exception {
		PICC_PK_Y1 = Y1;
		calculateSharedSecretP(); //berechnet P
		calculateNewPointG(); //berechnet G'
		PCD_SK_x2 = new FlexiBigInt("9D9A32DF93A57CCE33CA3CDD3457E33A976F293546C73550F397259C93BE0120",16);
//		PCD_SK_x2 = new FlexiBigInt(256, randomGenerator);
		if (debugging) logger.log(Level.INFO, "Private Key PCD_SK_x2:\n"+PCD_SK_x2.toString(16));
		
		PCD_PK_X2 = (PointGFP) ScalarMult.multiply4(PCD_SK_x2, pointG_strich);
		if (debugging) logger.log(Level.INFO, "Public Key PCD_PK_X2:\n"+PCD_PK_X2.toString());
		return PCD_PK_X2;
	}
	
	public PointGFP getX2(byte[] Y1Bytes) throws Exception {
		return getX2(bytesToPoint(Y1Bytes));
	}
	
	/** Erzeugt das finale Shared Secret K
	 * @param Y2 Zweiter öffentlicher Schlüssel Y2 der Karte
	 * @return Shared Secret K
	 */
	public byte[] getK(PointGFP Y2) {
		PICC_PK_Y2 = Y2;
		PointGFP  K = (PointGFP) ScalarMult.multiply4(PCD_SK_x2, PICC_PK_Y2);
		SharedSecret_K = K.getX().toByteArray();
		if (debugging) logger.log(Level.INFO, "Shared Secret K:\n"+HexString.bufferToHex(SharedSecret_K));
		K_enc = derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01});
		K_mac = derivateAES128Key(SharedSecret_K, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02});
		if (debugging) logger.log(Level.INFO, "K_enc:\n"+HexString.bufferToHex(K_enc));
		if (debugging) logger.log(Level.INFO, "K_mac:\n"+HexString.bufferToHex(K_mac));
		return SharedSecret_K;
	}
	
	public byte[] getK(byte[] Y2Bytes) throws Exception {
		return getK(bytesToPoint(Y2Bytes));
	}

	public byte[] getKenc() {
		return K_enc;
	}
	
	public byte[] getKmac() {
		return K_mac;
	}
	
	/** Dekodiert aus dem übergebenen Byte-Array einen PointGFP.
	 *  Das benötigte prime field p wird aus der dem Konstrukor übergebenen Kurve übernommen
	 *  Das erste Byte muss den Wert 0x04 enthalten (uncompressed point).
	 * @param value Byte Array der Form {0x04, x-Bytes[], y-Bytes[]}
	 * @return Point generiert aus den Input-Daten
	 * @throws Exception Falls das erste Byte nicht den Wert 0x04 enthält, enthält das übergebene Byte-Array offensichtlich keinen Punkt
	 */
	public PointGFP bytesToPoint(byte[] value) throws Exception {
		byte[] x = new byte[(value.length-1)/2];
		byte[] y = new byte[(value.length-1)/2];
		if (value[0]!=(byte)0x04) throw new Exception("No uncompressed Point found!");
		else {
			System.arraycopy(value, 1, x, 0, (value.length-1)/2);
			System.arraycopy(value, 1+((value.length-1)/2), y, 0, (value.length-1)/2);
			GFPElement xE = new GFPElement(new FlexiBigInt(x), orderp);
			GFPElement yE = new GFPElement(new FlexiBigInt(y), orderp);
			PointGFP point = new PointGFP(xE, yE, (EllipticCurveGFP) curve);
			return point;
		}
		
	}
	
	
	/** Key Derivation Function (KDF) siehe BSI TR-03110 Kapitel A.2.3
	 * Erzeugt AES-128 SchlÃŒssel aus einem Shared Secret
	 * @param K The shared secret Value (z.B. PIN, CAN, PUK oder abgeleitete MRZ siehe BSI TR-03110 Tabelle A.4)
	 * @param c A 32-bit, big-endian integer counter.
	 *          (byte)0x00000001 for en-/decoding
	 *          (byte)0x00000002 for MAC (checksum)
	 *          (byte)0x00000003 for deriving encryption keys from a password
	 * @return Abgeleiteter SchlÃŒssel als Byte-Array
	 */
	private byte[] derivateAES128Key(byte[] K, byte[] c) {
				
		byte[] mergedData = new byte[K.length+c.length];
		System.arraycopy(K, 0, mergedData, 0, K.length);
		System.arraycopy(c, 0, mergedData, K.length, c.length);
		
		byte[] checksum = calculateSHA1(mergedData);
		
		// keydata = H(K||c)
		// keydata sind die ersten 16 Byte der Hashfunktion ÃŒber "mergedData"
		byte [] keydata = new byte[16];
		System.arraycopy(checksum, 0, keydata, 0, 16);
		return keydata;
	}
	
	/** Key Derivation Function (KDF) siehe BSI TR-03110 Kapitel A.2.3
	 * Erzeugt AES-128 SchlÃŒssel aus einem Shared Secret
	 * @param K The shared secret Value (z.B. PIN, CAN, PUK oder abgeleitete MRZ siehe BSI TR-03110 Tabelle A.4)
	 * @param r A nonce. (Zufallszahl)
	 * @param c A 32-bit, big-endian integer counter.
	 *          (byte)0x00000001 for en-/decoding
	 *          (byte)0x00000002 for MAC (checksum)
	 *          (byte)0x00000003 for deriving encryption keys from a password
	 * @return Abgeleiteter SchlÃŒssel als Byte-Array
	 */
	private byte[] derivateAES128Key(byte[] K, byte[] c, byte[] r) {
				
		byte[] mergedData = new byte[K.length+r.length+c.length];
		
		System.arraycopy(K, 0, mergedData, 0, K.length);
		System.arraycopy(r, 0, mergedData, K.length, r.length);
		System.arraycopy(c, 0, mergedData, K.length+r.length, c.length);
		
		byte[] checksum = calculateSHA1(mergedData);
		
		//keydata = H(K||r||c)
		//keydata sind die ersten 16 Byte der Hashfunktion über "mergedData"
		byte [] keydata = new byte[16];
		System.arraycopy(checksum, 0, keydata, 0, 16);
		
		return keydata;
	}
	
	/** Dekodiert einen Block mit AES
	 * @param key Byte-Array enthält den AES-Schlüssel
	 * @param z decrypted block
	 * @return encrypted block
	 */
	private byte[] decryptAESblock(byte[] key, byte[] z) {
		byte[] s = new byte[16];
        KeyParameter encKey = new KeyParameter(key);
        BlockCipher cipher = new AESFastEngine();
		cipher.init(false, encKey);
		cipher.processBlock(z, 0, s, 0);
		return s;
	}
	
	/** Erzeugt aus dem Public Key 1 der Karte (PICC_PK_Y1) und dem Secret Key PCD_SK_x1 das erste Shared Secret P
	 * @throws Exception Falls PICC_PK_Y1 noch nicht gesetzt wurde (während getX2) wird diese Exception geworfen.
	 * 
	 */
	private void calculateSharedSecretP() throws Exception {
		if (PICC_PK_Y1==null) throw new Exception("PICC_PK_Y1 not initialized!");
		SharedSecret_P = (PointGFP) ScalarMult.multiply(PCD_SK_x1, PICC_PK_Y1);
		if (debugging) logger.log(Level.INFO, "Public Key PICC_PK_Y1:\n"+PICC_PK_Y1.toString()+"\nSharedSecret_P = PCD_SK_x1 * PICC_PK_Y1:\n"+SharedSecret_P.toString());
	}
		
	
	/**
	 * Erzeugt aus der nonce s, dem Punkt G und dem shared secret P den neuen Punkt G' 
	 * G' = s*G+P
	 * @throws Exception Falls nonce s noch nicht berechnet wurde (passiert während getX1) wird diese Exception geworfen
	 */
	private void calculateNewPointG() throws Exception {
		if (nonce_s==null) throw new Exception("nonce s not initialized!");
		FlexiBigInt ms = new FlexiBigInt(nonce_s);
		PointGFP g_temp = (PointGFP) ScalarMult.multiply4(ms, pointG);
		pointG_strich = (PointGFP) g_temp.add(SharedSecret_P);
		if (debugging) logger.log(Level.INFO, "New Point G':\n"+pointG_strich.toString());
	}

	
	/**
	 * Erstellt einen Logger
	 * @throws IOException 
	 */
	private void initializeLogger() throws IOException {
		logger = Logger.getLogger(Pace_old.class.getName());
//	    FileHandler fh = null;
//	    fh = new FileHandler();
//	    logger.addHandler(fh);
	    logger.setLevel(Level.ALL);
//	    SimpleFormatter formatter = new SimpleFormatter();
//	    fh.setFormatter(formatter);
	}
	
	/**
	 * Berechnet den SHA1-Wert des ÃŒbergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom ÃŒbergebenen Byte-Array
	 */
	private byte[] calculateSHA1(byte[] input) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException ex) {
		}

		md.update(input);
		return md.digest();
	}
	

}