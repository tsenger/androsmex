package de.tsenger.pace.junittests;

import java.util.Arrays;

import ext.org.bouncycastle.asn1.DERObjectIdentifier;

import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.paceASN1objects.CertificateHolderAuthorizationTemplate;
import junit.framework.TestCase;

public class CertificateHolderAuthorizationTemplateTest extends TestCase {
	
	private byte[] chat1 = HexString.hexToBuffer("7f4c12060904007f00070301020253050000000110");
	private byte[] chat2 = HexString.hexToBuffer("7f4c0e060904007f000703010201530123");

	public void testGetEncodedChat1() {
		DERObjectIdentifier id_AT = new DERObjectIdentifier("0.4.0.127.0.7.3.1.2.2");
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(id_AT);
		chat.setAuthorization(new byte[]{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x10});
		System.out.println(HexString.bufferToHex(chat.getEncodedChat()));
		assertTrue(Arrays.equals(chat.getEncodedChat(),chat1));
	}
	public void testGetEncodedChat2() {
		DERObjectIdentifier id_AT = new DERObjectIdentifier("0.4.0.127.0.7.3.1.2.1");
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(id_AT);
		chat.setAuthorization((byte)0x23);
		System.out.println(HexString.bufferToHex(chat.getEncodedChat()));
		assertTrue(Arrays.equals(chat.getEncodedChat(),chat2));
	}

}
