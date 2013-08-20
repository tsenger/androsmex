package de.tsenger.androsmex.bac;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.tsenger.androsmex.crypto.AmDESCrypto;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.tools.Crypto;
import de.tsenger.androsmex.tools.HexString;

public class BACFunctions {

	private boolean bacEstablished = false;

	private byte[] kenc = null;
	private byte[] kmac = null;
	private byte[] ksenc = null;
	private byte[] ksmac = null;
	
	private final byte[] ssc = new byte[8];

	private byte[] rndicc = null;
	private byte[] rndifd = null;
	
	private byte[] kicc = null;
	private byte[] kifd = null;

	/**
	 * Constants that help in determining whether or not a byte array is parity
	 * adjusted.
	 */
	private static final byte[] PARITY = { 8, 1, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0,
			8, 0, 2, 8, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 3, 0, 8,
			8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0, 8, 0, 0, 8, 0, 8, 8, 0,
			0, 8, 8, 0, 8, 0, 0, 8, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8,
			8, 0, 8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8,
			0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0,
			0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0,
			8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8,
			8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 0, 8, 8, 0, 8, 0, 0, 8, 8, 0, 0, 8,
			0, 8, 8, 0, 8, 0, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0, 0, 8, 0, 8,
			8, 0, 8, 0, 0, 8, 8, 0, 0, 8, 0, 8, 8, 0, 4, 8, 8, 0, 8, 0, 0, 8,
			8, 0, 0, 8, 0, 8, 8, 0, 8, 5, 0, 8, 0, 8, 8, 0, 0, 8, 8, 0, 8, 0,
			6, 8 };

	public BACFunctions(String mrz, byte[] cardChallenge) {
		this.rndicc = cardChallenge;
		
		String mrzInfo = calculateMrzInfo(mrz);
		kenc = calculateKENC(mrzInfo);
		kmac = calculateKMAC(mrzInfo);
		
		bacEstablished = false;
	}

	/**
	 * Erzeugt Daten für das Kommando MUTUAL AUTHENTICATION. Enthält E_ifd und M_ifd.
	 * 
	 * @return Daten für mutual authentication
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public byte[] getMutualAuthenticationCommand() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

		// 2. Generate an 8 byte random and a 16 byte random.
		rndifd = new byte[8];
		kifd = new byte[16];
		Random rand = new Random();
		rand.nextBytes(rndifd); // fill rndifd with random bytes
		rand.nextBytes(kifd); // fill kifd with random bytes

		// 3. Concatenate RND.IFD, RND.ICC and KIFD:
		byte[] s = new byte[32];
		
		// Fürs Testen: keine echten Zufallszahlen...
//		rndifd = new byte[] {(byte)0x78, (byte)0x17, (byte)0x23, (byte)0x86, (byte)0x0C, (byte)0x06, (byte)0xC2, (byte)0x26};
//		kifd   = new byte[] {(byte)0x0B, (byte)0x79, (byte)0x52, (byte)0x40, (byte)0xCB, (byte)0x70, (byte)0x49, (byte)0xB0,
//				(byte)0x1C, (byte)0x19, (byte)0xB3, (byte)0x3E, (byte)0x32, (byte)0x80, (byte)0x4F, (byte)0x0B};
		
		System.arraycopy(rndifd, 0, s, 0, rndifd.length);
		System.arraycopy(rndicc, 0, s, 8, rndicc.length);
		System.arraycopy(kifd, 0, s, 16, kifd.length);

		// 4. Encrypt S with TDES key Kenc:
		byte[] eifd = encryptTDES(kenc, s);

		// 5. Compute MAC over eifd with TDES key Kmac:
		byte[] mifd = Crypto.computeMAC(kmac, eifd);

		// 6. Construct command data for MUTUAL AUTHENTICATE and send command
		// APDU to the MRTD's chip:
		byte[] mu_data = new byte[eifd.length+mifd.length];
		System.arraycopy(eifd, 0, mu_data, 0, eifd.length);
		System.arraycopy(mifd, 0, mu_data, eifd.length, mifd.length);
		return mu_data;
	}
	
	/**
	 * Verifiziert die Response der Karte auf das Kommando Mutual Authentication,
	 * berechnet die Session Keys sowie den initialen Wert des Send Sequence Counters.
	 * @param mu_response Response der Karte auf das Kommando Mutual Authentication
	 * @return BAC erfolgreich durchgeführt
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public SecureMessaging establishBAC(byte[] mu_response) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// 16.Decrypt and verify received data and compare received RND.IFD with
		// generated RND.IFD.
		byte[] eicc = new byte[32];
		byte[] micc = new byte[8];
		byte[] r = null;
		System.arraycopy(mu_response, 0, eicc, 0, eicc.length);
		System.arraycopy(mu_response, 32, micc, 0, micc.length);

		if (Arrays.equals(Crypto.computeMAC(kmac, eicc), micc)) {
			r = decryptTDES(kenc, eicc);
			byte[] received_rndifd = new byte[8];
			System.arraycopy(r, 8, received_rndifd, 0, received_rndifd.length);
			System.out.println("r: "+HexString.bufferToHex(r)+"\nRND.IFD : "+HexString.bufferToHex(rndifd)+"\nRRND.IFD: "+HexString.bufferToHex(received_rndifd));
			if (Arrays.equals(rndifd, received_rndifd)) {
				kicc = new byte[16];
				System.arraycopy(r, 16, kicc, 0, kicc.length);

				calculateSessionKeys(kifd, kicc);
				
				// Berechne Send Sequence Counter SSC
				System.arraycopy(rndicc, 4, ssc, 0, 4);
				System.arraycopy(rndifd, 4, ssc, 4, 4);
				bacEstablished = true;
			} else {
				bacEstablished = false;
			}
		} else {
			bacEstablished = false;
		}
		return new SecureMessaging(new AmDESCrypto(), kenc, ksmac, ssc);
	}

	/**
	 * Berechnet die Sessionskey mit Hilfe von K_ifd und K_icc und speichert sie in den globalen Variablen ksenc und ksmac
	 * @param kifd K_ifd ist der 16 Byte-Schlüssel des Lesers
	 * @param kicc K_icc ist der 16 Byte-Schlüssel der Karte
	 */
	private void calculateSessionKeys(byte[] kifd, byte[] kicc) {

		byte[] kseed = Crypto.xorArray(kicc, kifd);

		// 18.Calculate Session Keys (KS_ENC and KS_MAC):
		ksenc = computeKey(kseed, new byte[] { 0, 0, 0, 1 });
		ksmac = computeKey(kseed, new byte[] { 0, 0, 0, 2 });
	}


	
	

	/**
	 * Verschlüsselt das übergebene Byte-Array 'plaintext' mit Hilfe des
	 * Triple-DES Algorithmus. Der Schlüssel wird in der Variable 'key'
	 * erwartet. IV = 0
	 * 
	 * @param key
	 *            Der 3DES-Schlüssel als Byte-Array.
	 * @param plaintext
	 *            Das zu verschlüsselnde Byte-Array
	 * @return Chiffre
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private byte[] encryptTDES(byte[] key, byte[] plaintext) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return Crypto.tripleDES(true, key, plaintext);
	}

	/**
	 * Entschlüsselt das übergebene Byte-Array 'ciphertext' mit Hilfe des
	 * Triple-DES Algorithmus. Der Schlüssel wird in der Variable 'key'
	 * erwartet. IV = 0
	 * 
	 * @param key
	 *            Der 3DES-Schlüssel als Byte-Array.
	 * @param plaintext
	 *            Das zu verschlüsselnde Byte-Array
	 * @return Chiffre
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private byte[] decryptTDES(byte[] key, byte[] ciphertext) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		return Crypto.tripleDES(false, key, ciphertext);
	}

	

	/**
	 * Berechnet aus der der zweiten Zeile einer zweizeilige MRZ die
	 * MRZ_information. MRZ_information besteht aus okumentennummer +
	 * Geburtsdatum + Gültigkeitsdatum (jeweils mit Prüfziffer)
	 * 
	 * @param mrz
	 *            Zweite Zeile der MRZ (nur bei zweizeiliger MRZ)
	 * @return String MRZ_information
	 */
	private String calculateMrzInfo(String mrz) {
		String documentNr = mrz.substring(0, 10); // +1 checkdiget
		String dateOfBirth = mrz.substring(13, 20); // +1 checkdiget
		String dateOfExpiry = mrz.substring(21, 28); // +1 checkdiget
		String mrzInfo = documentNr + dateOfBirth + dateOfExpiry;
		return mrzInfo;
	}

	/**
	 * Berechnet aus der MRZ_information den Schlüssel K_mac
	 * 
	 * @param mrzInfo
	 *            String MRZ_information besteht aus Dokumentennummer +
	 *            Geburtsdatum + Gültigkeitsdatum (jeweils mit Prüfziffer) aus
	 *            der MRZ
	 * @return Liefert den Wert von K_mac als Byte Array zurück
	 */
	private byte[] calculateKMAC(String mrzInfo) {
		byte[] mrzinfobytes = mrzInfo.getBytes();
		byte[] kseed = calculateKSeed(mrzinfobytes);
		return computeKey(kseed, new byte[] { 0, 0, 0, 2 });
	}

	/**
	 * Berechnet aus der MRZ_information den Schlüssel K_enc
	 * 
	 * @param mrzInfo
	 *            String MRZ_information besteht aus Dokumentennummer +
	 *            Geburtsdatum + Gültigkeitsdatum (jeweils mit Prüfziffer) aus
	 *            der MRZ
	 * @return Liefert den Wert von K_enc als Byte Array zurück
	 */
	private byte[] calculateKENC(String mrzInfo) {
		byte[] mrzInfoBytes = mrzInfo.getBytes();
		byte[] kseed = calculateKSeed(mrzInfoBytes);
		return computeKey(kseed, new byte[] { 0, 0, 0, 1 });
	}

	/**
	 * Berechnet den Wert K_seed von einem als Byte-Array übergebenen
	 * MRZ_information
	 * 
	 * @param mrzInfoBytes
	 *            Enthält die MRZ_information (siehe calculateMrzInfo)
	 * @return K_seed sind die ersten 16 Bytes von SHA1(MRZ_information)
	 */
	private byte[] calculateKSeed(byte[] mrzInfoBytes) {
		byte[] hash = calculateSHA1(mrzInfoBytes);
		byte[] kseed = new byte[16];
		for (int i = 0; i < 16; i++)
			kseed[i] = hash[i];
		return kseed;
	}

	/**
	 * Berechnet den SHA1-Wert des übergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom übergebenen Byte-Array
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

	/**
	 * computeKey berechnet die Basic Access Keys. Parameter c bestimmt ob K_ENC
	 * für die Verschlüsselung oder K_MAC für das Secure Messaging berechnet
	 * wird. Das Ergebnis ist sind jeweils ein 2Key-3DES-Schlüssel mit
	 * korrigierten Parity Bits.
	 * 
	 * @param kseed
	 *            Wert für K_seed (siehe calculateKseed)
	 * @param c
	 *            Wenn c='0x 00 00 00 01' wird K_ENC berechnet. Wenn c='0x 00 00
	 *            00 02' wird K_MAC berechnet.
	 * @return Gibt den 2-Key-3DES-Schlüssel in 24 Bytes (Ka, Kb, Ka) aus.
	 */
	private byte[] computeKey(byte[] kseed, byte[] c) {
		byte[] d = new byte[20];
		System.arraycopy(kseed, 0, d, 0, kseed.length);
		System.arraycopy(c, 0, d, 16, c.length);

		byte[] hd = calculateSHA1(d);

		byte[] ka = new byte[8];
		byte[] kb = new byte[8];

		System.arraycopy(hd, 0, ka, 0, ka.length);
		System.arraycopy(hd, 8, kb, 0, kb.length);

		// Adjust Parity-Bits
		adjustParity(ka, 0);
		adjustParity(kb, 0);

		byte[] key = new byte[24];
		System.arraycopy(ka, 0, key, 0, 8);
		System.arraycopy(kb, 0, key, 8, 8);
		System.arraycopy(ka, 0, key, 16, 8);

		return key;
	}

	/**
	 * <p>
	 * Adjust the parity for a raw key array. This essentially means that each
	 * byte in the array will have an odd number of '1' bits (the last bit in
	 * each byte is unused.
	 * </p>
	 * 
	 * @param kb
	 *            The key array, to be parity-adjusted.
	 * @param offset
	 *            The starting index into the key bytes.
	 */
	private void adjustParity(byte[] key, int offset) {
		for (int i = offset; i < 8; i++) {
			key[i] ^= (PARITY[key[i] & 0xff] == 8) ? 1 : 0;
		}
	}

}
