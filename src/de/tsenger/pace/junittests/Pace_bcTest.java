package de.tsenger.pace.junittests;

import java.math.BigInteger;
import java.util.Arrays;


import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import ext.org.bouncycastle.asn1.x9.X9ECParameters;
import ext.org.bouncycastle.math.ec.ECCurve;
import ext.org.bouncycastle.math.ec.ECCurve.Fp;
import ext.org.bouncycastle.math.ec.ECFieldElement;
import ext.org.bouncycastle.math.ec.ECPoint;

import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.Pace;
import de.tsenger.pace.paceASN1objects.PaceInfo_bc;
import junit.framework.TestCase;

public class Pace_bcTest extends TestCase {
	
	private String z = "e6d5956aad397c35ea4be034da2d81a5"; //encrypted nonce
	
	private Pace paceObject = null;
	
	
	protected void setUp() throws Exception {
		super.setUp();
		paceObject = new Pace(new PaceInfo_bc(new DERObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2"), 2, 13));
        paceObject.debug(true);
	}

//	public void testGetX1() {
//		ECPoint X1 = paceObject.getX1("123456", HexString.hexToBuffer(z));
//		assertTrue(X1!=null);
//	}
	
//	public void testGetX2() {
//		ECPoint X1 = paceObject.getX1("123456", HexString.hexToBuffer(z));
//		assertTrue(X1!=null);
//	}
	
	public void testPACE() {
		ECPoint X1 = paceObject.getX1("819955", HexString.hexToBuffer(z));
		ECPoint X2 = null;
		try {
			X2 = paceObject.getX2(getY1());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] K = paceObject.getK(getY2());
		
		System.out.println("Shared Secret K: "+HexString.bufferToHex(K));
		System.out.println("K_enc: "+HexString.bufferToHex(paceObject.getKenc()));
		System.out.println("K_mac: "+HexString.bufferToHex(paceObject.getKmac()));
		
		assertTrue(Arrays.equals(HexString.hexToBuffer("ebfa52f51de10177dff7b4c99dfe8a59"), paceObject.getKenc()));
	}
	
	private ECPoint.Fp getY1() {
		BigInteger picc_x = new BigInteger("8500dae6daf5033ad3579cb916b5cb815713ecf760952dcf77f529581804a152",16);
		BigInteger picc_y = new BigInteger("287a2afcd4f6d55cb4edc4597c9cbcb96adb8bc57e188fbe29c37a6fa8788177",16);
		X9ECParameters cp = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
		ECCurve.Fp curve = (Fp) cp.getCurve();
		ECFieldElement.Fp mx = new ECFieldElement.Fp(curve.getQ(), picc_x);
		ECFieldElement.Fp my = new ECFieldElement.Fp(curve.getQ(), picc_y);
		ECPoint.Fp Y1 = new ECPoint.Fp(curve, mx, my);
		System.out.println("Y1 ECPoint:\n"+HexString.bufferToHex(Y1.getEncoded()));
		System.out.println("Y1 Q:\n"+curve.getQ().toString(16));
		return Y1;
	}
	
	private ECPoint.Fp getY2() {
		BigInteger picc_x2 = new BigInteger("8de76515ad66022bfec3ade33449fefb86104ffa233e4a2f4b2f21281acf0903",16);
		BigInteger picc_y2 = new BigInteger("1bbf5b9ccc9b0aa5dd98f2cd8fd742c8df9949995c57dc68b95f61429857b425",16);
		X9ECParameters cp = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
		ECCurve.Fp curve = (Fp) cp.getCurve();
		ECFieldElement.Fp mx = new ECFieldElement.Fp(curve.getQ(), picc_x2);
		ECFieldElement.Fp my = new ECFieldElement.Fp(curve.getQ(), picc_y2);
		ECPoint.Fp Y2 = new ECPoint.Fp(curve, mx, my);
		System.out.println("Y2 ECPoint:\n"+HexString.bufferToHex(Y2.getEncoded()));
		System.out.println("Y2 Q:\n"+curve.getQ().toString(16));
		return Y2;
	}
	

}
