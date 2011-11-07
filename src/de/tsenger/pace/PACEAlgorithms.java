package de.tsenger.pace;

import codec.asn1.ASN1ObjectIdentifier;

public class PACEAlgorithms {
	//TODO Liste vervollständigen. Siehe TR-03110 A.1.1.1 PACE
	public static ASN1ObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.1");
	public static ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
	public static ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.3");
	public static ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.4");

}
