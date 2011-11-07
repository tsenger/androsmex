package de.tsenger.androsmex.pace.junittests;

import java.math.BigInteger;

import junit.framework.TestCase;

import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.Fp;

import de.tsenger.androsmex.pace.paceASN1objects.AuthenticationToken;
import de.tsenger.androsmex.tools.HexString;

public class AuthenticationTokenTest extends TestCase {

	ECCurve.Fp curve = null;

	@Override
	protected void setUp() throws Exception {
		X9ECParameters cp = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
		Fp pointG = (Fp) cp.getG();
		curve = (org.spongycastle.math.ec.ECCurve.Fp) cp.getCurve();
		
	}
	
	public void testgetPCDToken() {
		DERObjectIdentifier oid = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
		BigInteger picc_x = new BigInteger("8de76515ad66022bfec3ade33449fefb86104ffa233e4a2f4b2f21281acf0903",16);
		BigInteger picc_y = new BigInteger("1bbf5b9ccc9b0aa5dd98f2cd8fd742c8df9949995c57dc68b95f61429857b425",16);
		ECFieldElement mx = new ECFieldElement.Fp(curve.getQ(), picc_x);
		ECFieldElement my = new ECFieldElement.Fp(curve.getQ(), picc_y);
		ECPoint.Fp Y2 = new ECPoint.Fp(curve, mx,my);
		
		AuthenticationToken at = new AuthenticationToken(oid,Y2);
		byte[] mac = at.getToken(HexString.hexToBuffer("b5da37cdf2ef845ca06bf62e3543c970"));
		System.out.println("T_PCD:\n"+HexString.bufferToHex(mac));
		assertTrue(true);
	}
	
	public void testgetPICCToken() {
		DERObjectIdentifier oid = new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2");
		BigInteger picc_x = new BigInteger("7f60a5a5ec16ac27c0a7fd45f0003fae5165b1bb909ad45b901f154a46770b80",16);
		BigInteger picc_y = new BigInteger("52101b2f353853b55f96724735cba8016d238837bf57ecb615fffaf65783f89b",16);
		ECFieldElement mx = new ECFieldElement.Fp(curve.getQ(), picc_x);
		ECFieldElement my = new ECFieldElement.Fp(curve.getQ(), picc_y);
		ECPoint.Fp X2 = new ECPoint.Fp(curve, mx,my);
		
		AuthenticationToken at = new AuthenticationToken(oid,X2);
		byte[] mac = at.getToken(HexString.hexToBuffer("b5da37cdf2ef845ca06bf62e3543c970"));
		System.out.println("T_PICC:\n"+HexString.bufferToHex(mac));
		assertTrue(true);
	}

}