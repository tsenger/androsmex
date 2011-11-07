package de.tsenger.androsmex.pace.paceASN1objects;

import java.io.IOException;

import ext.org.bouncycastle.asn1.ASN1EncodableVector;
import ext.org.bouncycastle.asn1.ASN1Sequence;
import ext.org.bouncycastle.asn1.DERApplicationSpecific;
import ext.org.bouncycastle.asn1.DEROctetString;
import ext.org.bouncycastle.asn1.DERTaggedObject;
import ext.org.bouncycastle.asn1.DERTags;


/** De-/Kodiert die ASN1-Strukturen die für PACE (General Authenticate) benötigt werden. 
 * @author Tobias Senger
 *
 */
public class DynamicAuthenticationData {

	private DERTaggedObject encryptedNonce80 = null; // Tag 0x80
	private DERTaggedObject mappingData81 = null; // Tag 0x81
	private DERTaggedObject mappingData82 = null; // Tag 0x82
	private DERTaggedObject ephemeralPK83 = null; // Tag 0x83
	private DERTaggedObject ephemeralPK84 = null; // Tag 0x84
	private DERTaggedObject authToken85 = null; // Tag 0x85
	private DERTaggedObject authToken86 = null; // Tag 0x86
	private DERTaggedObject CertificateAuthorityReference87 = null; // Tag 0x87 most recent CAR
	private DERTaggedObject CertificateAuthorityReference88 = null; // Tag 0x88 most recent CAR

	/**
	 * Setzt die Mapping Data (Tag 0x81)
	 * 
	 * @param data
	 *            Elliptic Curve Point (ECDH) oder BigInter (DH)
	 */
	public void setMappingData81(byte[] data) {
		mappingData81 = new DERTaggedObject(false, 0x01, new DEROctetString(data));
	}
	
	/**
	 * Setzt den Ephemeral Public Key (Tag 0x81)
	 * 
	 * @param data
	 *            Elliptic Curve Point (ECDH) oder BigInter (DH)
	 */
	public void setEphemeralPK83(byte[] data) {
		ephemeralPK83 = new DERTaggedObject(false, 0x03, new DEROctetString(data));
	}

	/**
	 * Setzt das Authentication Token (Tag 0x85)
	 * 
	 * @param data
	 *            Token
	 */
	public void setAuthenticationToken85(byte[] authBytes) {
		authToken85 = new DERTaggedObject(false, 0x05, new DEROctetString(
				authBytes));
	}

	public byte[] getEncryptedNonce80() {
		if (encryptedNonce80 != null) {
			DEROctetString ostr = (DEROctetString) encryptedNonce80.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getMappingData82() {
		if (mappingData82 != null) {
			DEROctetString ostr = (DEROctetString) mappingData82.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getEphemeralPK84() {
		if (ephemeralPK84 != null) {
			DEROctetString ostr = (DEROctetString) ephemeralPK84.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getAuthToken86() {
		if (authToken86 != null) {
			DEROctetString ostr = (DEROctetString) authToken86.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getCAR87() {
		if (CertificateAuthorityReference87 != null) {
			DEROctetString ostr = (DEROctetString) CertificateAuthorityReference87.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getCAR88() {
		if (CertificateAuthorityReference88 != null) {
			DEROctetString ostr = (DEROctetString) CertificateAuthorityReference88.getObjectParser(DERTags.OCTET_STRING, false);
			return ostr.getOctets();
		}
		else return null;
	}

	public byte[] getDEREncoded() {

		ASN1EncodableVector asn1vec = new ASN1EncodableVector();
		if (mappingData81 != null) {
			asn1vec.add(mappingData81);
		}
		if (ephemeralPK83 != null) {
			asn1vec.add(ephemeralPK83);
		}
		if (authToken85 != null) {
			asn1vec.add(authToken85);
		}

		DERApplicationSpecific dynamicAuthenticationData = new DERApplicationSpecific(0x1C, asn1vec); //Application specific + 0x1c = 0x7C
		return dynamicAuthenticationData.getDEREncoded();
	}

	public void decode(byte[] data) {

		DERApplicationSpecific das = null;
		ASN1Sequence seq = null;
		try {
			das = (DERApplicationSpecific) DERApplicationSpecific.fromByteArray(data);
			seq = ASN1Sequence.getInstance(das.getObject(DERTags.SEQUENCE));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		System.out.println(org.bouncycastle.asn1.util.ASN1Dump.dumpAsString(das));
//		System.out.println("TAG: " + das.getApplicationTag());
//		System.out.println("Value: \n" + HexString.bufferToHex(das.getContents()));
//		System.out.println("Size: \n" + seq.size());

		for (int i = 0; i < seq.size(); i++) {
			DERTaggedObject temp = (DERTaggedObject) seq.getObjectAt(i);
			switch (temp.getTagNo()) {
			case 0:
				encryptedNonce80 = temp;
				break;
			case 1:
				mappingData81 = temp;
				break;
			case 2:
				mappingData82 = temp;
				break;
			case 3:
				ephemeralPK83 = temp;
				break;
			case 4:
				ephemeralPK84 = temp;
				break;
			case 5:
				authToken85 = temp;
				break;
			case 6:
				authToken86 = temp;
				break;
			case 7:
				CertificateAuthorityReference87 = temp;
				break;
			case 8:
				CertificateAuthorityReference88 = temp;
				break;
			}
		}

	}
}
