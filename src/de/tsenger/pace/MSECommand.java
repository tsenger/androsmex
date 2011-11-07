package de.tsenger.pace;

import java.io.IOException;

import ext.org.bouncycastle.asn1.DERInteger;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.asn1.DEROctetString;
import ext.org.bouncycastle.asn1.DERTaggedObject;

import de.tsenger.androsmex.CommandAPDU;
import de.tsenger.pace.paceASN1objects.CertificateHolderAuthorizationTemplate;

public class MSECommand extends CommandAPDU{
	
	public static int setAT_PACE = 1;
	public static int setAT_CA = 2;
	public static int setAT_TA = 3;
	
	public static int KeyReference_MRZ = 1;
	public static int KeyReference_CAN = 2;
	public static int KeyReference_PIN = 3;
	public static int KeyReference_PUK = 4;
	
	private byte CLASS = (byte)0x00;
	private byte INS = (byte)0x22; //Instruction Byte: Message Security Environment
	private byte[] P1P2 = null;
	private byte[] CMR = null;
	private byte[] passwordReferenz = null;
	private byte[] keyName = null;
	private byte[] privateKeyReference = null;
	private byte[] chatBytes = null;

	public MSECommand(int size) {
		super(size);
		// TODO Auto-generated constructor stub
	}
	
	/** Setzt das zu verwendende Authentication Template (PACE, CA oder TA)
	 * @param at {@link de.tsenger.pace.MSECommand.setAT_PACE}, 
	 * {@link de.tsenger.pace.MSECommand.setAT_CA},
	 * {@link de.tsenger.pace.MSECommand.setAT_TA} 
	 */
	public void setAT(int at) {
		if (at==setAT_PACE) P1P2 = new byte[] {(byte)0xC1, (byte)0xA4};
		if (at==setAT_CA) P1P2 = new byte[] {(byte)0x41, (byte)0xA4};
		if (at==setAT_TA) P1P2 = new byte[] {(byte)0x81, (byte)0xA4};		
	}
	
	/** Setzt die OID des zu verwendenden Protokolls
	 * @param protocol Das zu verwendende Protokoll
	 */
	public void setCMR(DERObjectIdentifier protocol) {
			
		DERTaggedObject to = new DERTaggedObject(false, 0x00, protocol);
		try {
			CMR = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt die OID des zu verwendenden Protokolls
	 * @param protocol Das zu verwendende Protokoll
	 */
	public void setCMR(String protocol) {
			
		DERTaggedObject to = new DERTaggedObject(false, 0x00, new DERObjectIdentifier(protocol));
		try {
			CMR = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt das Tag 0x83 (Reference of public / secret key) für PACE
	 * @param kr Referenziert das verwendete Passwort:
	 * 1: MRZ
	 * 2: CAN
	 * 3: PIN
	 * 4: PUK
	 */
	public void setKeyReference(int kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DERInteger(kr));
		try {
			passwordReferenz = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt das Tag 0x83 (Reference of public / secret key) für Terminal Authentication
	 * @param kr String der den Namen des Public Keys des Terminals beinhaltet (ISO 8859-1 kodiert)
	 */
	public void setKeyReference(String kr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x03, new DEROctetString(kr.getBytes()));
		try {
			keyName = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** Setzt das Tag 0x84 (Reference of a private key / Reference for computing a session key)
	 * @param pkr Bei PACE wird der Index der zu verwendenden Domain Parameter angegeben
	 * Bei CA wird der Index des zu verwendenden Private Keys angegeben
	 * Bei RI wird der Index des zu verwendenden Private Keys angegeben
	 */
	public void setPrivateKeyReference(byte pkr) {
		DERTaggedObject to = new DERTaggedObject(false, 0x04, new DERInteger(pkr));
		try {
			privateKeyReference = to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void setAuxiliaryAuthenticatedData() {
		// TODO noch zu implementieren, Tag 0x67
	}
	
	public void setEphemeralPublicKey() {
		// TODO noch zu implementieren, Tag 0x91
	}
	
	public void setCHAT(CertificateHolderAuthorizationTemplate chat) {
		chatBytes = chat.getEncodedChat();
	}
	
	
	/* Konstruiert aus den gesetzten Objekten eine MSE-Command-APDU und liefert diese als Byte-Array zurück.
	 * @see de.tsenger.androsmex.CommandAPDU#getBytes()
	 */
	public byte[] getBytes() {
		append(CLASS);
		append(INS);
		append(P1P2);
		int lc = 0;
		if (CMR!=null) lc += CMR.length;
		if (passwordReferenz!=null) lc += passwordReferenz.length;
		if (privateKeyReference!=null) lc += privateKeyReference.length;
		if (chatBytes!=null) lc += chatBytes.length;
		
		append((byte) lc);
		append(CMR);
		append(passwordReferenz);
		append(privateKeyReference);
		append(chatBytes);
		return super.getBytes();
	}
	

}
