package de.tsenger.androsmex.pace;

import org.spongycastle.asn1.DERObjectIdentifier;

public class PACEOID {
	//TODO Liste vervollständigen. Siehe TR-03110 A.1.1.1 PACE
	public static DERObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.1");
	public static DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
	public static DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.3");
	public static DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.4");
	
	public static DERObjectIdentifier id_IS = new DERObjectIdentifier("0.4.0.127.0.7.3.1.2.1");
	public static DERObjectIdentifier id_AT = new DERObjectIdentifier("0.4.0.127.0.7.3.1.2.2");
	public static DERObjectIdentifier id_ST = new DERObjectIdentifier("0.4.0.127.0.7.3.1.2.3");
	
	public static DERObjectIdentifier id_TA = new DERObjectIdentifier("0.4.0.127.0.7.2.2.2");
	
	public static DERObjectIdentifier id_CA_DH = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.1");
	public static DERObjectIdentifier id_CA_DH_3DES_CBC_CBC = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.1.1");
	public static DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_128 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.1.2");
	public static DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_192 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.1.3");
	public static DERObjectIdentifier id_CA_DH_3DES_CBC_CMAC_256 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.1.4");
	public static DERObjectIdentifier id_CA_ECDH = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.2");
	public static DERObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.2.1");
	public static DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_128 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.2.2");
	public static DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_192 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.2.3");
	public static DERObjectIdentifier id_CA_ECDH_3DES_CBC_CMAC_256 = new DERObjectIdentifier("0.4.0.127.0.7.2.2.3.2.4");

}
