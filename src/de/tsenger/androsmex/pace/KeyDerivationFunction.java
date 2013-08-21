/**
 * 
 */
package de.tsenger.androsmex.pace;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA256Digest;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class KeyDerivationFunction {
	
	private byte[] mergedData = null;
	
	
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
	
	/**
	 * 
	 * Das MRZ-Passwort besteht aus dem SHA1-Wert der Dokumentennummer +
	 * Geburtsdatum + Gültigkeitsdatum (jeweils mit Prüfziffer)
	 * 
	 * @param documentNr Dokumentennummer plus Prüfziffer
	 * @param dateOfBirth Geburtsdatum aus der MRZ plus Prüfziffer
	 * @param dateOfExpiry Gültigkeitsdatum aus der MRZ plus Prüfziffer
	 * @return K = SHA-1(Serial Number||Date of Birth||Date of Expiry)
	 */
	public static byte[] getMRZBytes(String documentNr, String dateOfBirth, String dateOfExpiry) {
		String mrzInfo = documentNr + dateOfBirth + dateOfExpiry;
		byte[] passwordBytes = mrzInfo.getBytes();
		
		byte[] K = new byte[20];
		
		SHA1Digest sha1 = new SHA1Digest();
		sha1.update(passwordBytes, 0, passwordBytes.length);
		sha1.doFinal(K, 0);
		
		return K;		
	}

	
	/**
	 * Constructor for Key Derivation Function (KDF) siehe BSI TR-03110 Kapitel A.2.3
	 *  
	 * @param K
	 *            The shared secret Value (z.B. PIN, CAN, PUK als Byte Array oder abgeleitete
	 *            MRZ siehe BSI TR-03110 Tabelle A.4)
	 * @param c
	 *            A 32-bit, big-endian integer counter. 1 for
	 *            en-/decoding, 2 for MAC (checksum),
	 *            3 for deriving encryption keys from a password
	 * @throws Exception c must be 1, 2 or 3
	 */
	public KeyDerivationFunction(byte[] K, int c) throws IllegalArgumentException {
		
		if (c<=0||c>3) throw new IllegalArgumentException("c must be 1, 2 or 3!");
		
		byte[] cBytes = intToByteArray(c);
		
		mergedData = new byte[K.length + cBytes.length];
		System.arraycopy(K, 0, mergedData, 0, K.length);
		System.arraycopy(cBytes, 0, mergedData, K.length, cBytes.length);
	}

	
	/**
	 * Constructor for Key Derivation Function (KDF) siehe BSI TR-03110 Kapitel A.2.3
	 *  
	 * @param K
	 *            The shared secret Value (z.B. PIN, CAN, PUK oder abgeleitete
	 *            MRZ siehe BSI TR-03110 Tabelle A.4)
	 * @param r   a nonce r
	 * @param c
	 *            A 32-bit, big-endian integer counter. 1 for
	 *            en-/decoding, 2 for MAC (checksum),
	 *            3 for deriving encryption keys from a password
	 * @throws Exception c must be 1, 2 or 3
	 */
	public KeyDerivationFunction(byte[] K, byte[] r, int c) throws Exception {
		
		if (c<=0||c>3) throw new Exception("c must be 1, 2 or 3!");
		
		byte[] cBytes = intToByteArray(c);
		
		mergedData = new byte[K.length + +r.length + cBytes.length];
		System.arraycopy(K, 0, mergedData, 0, K.length);
		System.arraycopy(r, 0, mergedData, K.length, r.length);
		System.arraycopy(cBytes, 0, mergedData, K.length + r.length, cBytes.length);
	}
	
	/**
	 * Erzeugt 3DES Schlüssel
	 * 
	 * @return 112bit-3DES-Schlüssel in 24 Bytes mit korrekten Parity-Bits
	 */
	public byte[] getDESedeKey() {
		
		byte[] checksum = new byte[20];
		
		SHA1Digest sha1 = new SHA1Digest();
		sha1.update(mergedData, 0, mergedData.length);
		sha1.doFinal(checksum, 0);
		
		byte[] ka = new byte[8];
		byte[] kb = new byte[8];

		System.arraycopy(checksum, 0, ka, 0, ka.length);
		System.arraycopy(checksum, 8, kb, 0, kb.length);

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
	 * Erzeugt AES-128 Schlüssel
	 * 
	 * @return Schlüssel als Byte-Array
	 */
	public byte[] getAES128Key() {

		byte[] checksum = new byte[20];
		
		SHA1Digest sha1 = new SHA1Digest();
		sha1.update(mergedData, 0, mergedData.length);
		sha1.doFinal(checksum, 0);

		// keydata = H(K||c)
		// keydata sind die ersten 16 Byte der Hashfunktion über "mergedData"
		byte[] keydata = new byte[16];
		System.arraycopy(checksum, 0, keydata, 0, 16);
		return keydata;
	}
	
	/**
	 * Erzeugt AES-192 Schlüssel
	 * 
	 * @return Schlüssel als Byte-Array
	 */
	public byte[] getAES192Key() {

		byte[] checksum = getAES256Key();
		byte[] keydata = new byte[24];
		System.arraycopy(checksum, 0, keydata, 0, 24);
		return keydata;
	}
	
	/**
	 * Erzeugt AES-256 Schlüssel
	 * 
	 * @return Schlüssel als Byte-Array
	 */
	public byte[] getAES256Key() {

		byte[] checksum = new byte[32];
		
		SHA256Digest sha256 = new SHA256Digest();
		sha256.update(mergedData, 0, mergedData.length);
		sha256.doFinal(checksum, 0);

		return checksum;
	}
	
	/**
	 * Adjust the parity for a raw key array. This essentially means that each
	 * byte in the array will have an odd number of '1' bits (the last bit in
	 * each byte is unused.
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
	
	/**
	 * @param c
	 * @return
	 */
	private byte[] intToByteArray(int c) {
		// int -> byte[]
		byte[] intBytes = new byte[4];
		for (int i = 0; i < 4; ++i) {
		    int shift = i << 3; // i * 8
		    intBytes[3-i] = (byte)((c & (0xff << shift)) >>> shift);
		}
		return intBytes;
	}
	

}
