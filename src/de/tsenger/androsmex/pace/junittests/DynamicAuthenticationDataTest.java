package de.tsenger.androsmex.pace.junittests;

import java.util.Arrays;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.ec.parameters.CurveRegistry;
import de.tsenger.androsmex.pace.paceASN1objects.DynamicAuthenticationData;
import de.tsenger.androsmex.tools.HexString;
import junit.framework.TestCase;

public class DynamicAuthenticationDataTest extends TestCase {
	
	private DynamicAuthenticationData dad = null;
	byte[] d1 = HexString.hexToBuffer("7C438141043DFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A");
	byte[] d82 = HexString.hexToBuffer("7C438241043DFCF75820C986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A");
	byte[] d2 = HexString.hexToBuffer("7C438341043DFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A");
	byte[] d84 = HexString.hexToBuffer("7C438441043DFCF75820C986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A");
	byte[] d3 = HexString.hexToBuffer("7C198608A2658C2F38600B0F870D44454356434141543030303031");

	protected void setUp() throws Exception {
		super.setUp();
		dad = new DynamicAuthenticationData();
	}

	public void testSetMappingDataPointGFP() {
		dad.setMappingData81(getBytes(getY1()));
		System.out.println("Test1:\n"+HexString.bufferToHex(dad.getDEREncoded()));
		assertTrue(Arrays.equals(dad.getDEREncoded(), d1));
	}

	public void testGetMappingData82() {
		dad.decode(d82);
		assertTrue(Arrays.equals(dad.getMappingData82(), HexString.hexToBuffer("043DFCF75820C986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A")));
	}

	public void testSetEphemeralPKPointGFP() {
		dad.setEphemeralPK83(getBytes(getY1()));
		System.out.println("Test2:\n"+HexString.bufferToHex(dad.getDEREncoded()));
		assertTrue(Arrays.equals(dad.getDEREncoded(), d2));
	}

	public void testGetEphemeralPK84() {
		dad.decode(d84);
		assertTrue(Arrays.equals(dad.getEphemeralPK84(), HexString.hexToBuffer("043DFCF75820C986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A")));
	}

	public void testDecodeDAD() {
		dad.decode(d3);
		System.out.println("AuthToken:\n"+HexString.bufferToHex(dad.getAuthToken86()));
		System.out.println("CAR87:\n"+HexString.bufferToHex(dad.getCAR87()));
		assertTrue(Arrays.equals(HexString.hexToBuffer("44454356434141543030303031"),dad.getCAR87()));
	}
	
	private PointGFP getY1() {
		CurveRegistry.BrainpoolP256r1 cP = new CurveRegistry.BrainpoolP256r1();
		FlexiBigInt picc_x = new FlexiBigInt("3DFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B",16);
		FlexiBigInt picc_y = new FlexiBigInt("45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A",16);
		EllipticCurveGFP curve = (EllipticCurveGFP) cP.getE();
		GFPElement mx = new GFPElement(picc_x, curve.getQ());
		GFPElement my = new GFPElement(picc_y, curve.getQ());
		PointGFP Y1 = new PointGFP(mx,my,curve);
		return Y1;
	}
	
	private byte[] getBytes(PointGFP point) {
		byte[] x = point.getX().toByteArray();
		byte[] y = point.getY().toByteArray();
		byte[] pointbytes = new byte[1 + x.length + y.length];
		pointbytes[0] = (byte) 0x04;
		System.arraycopy(x, 0, pointbytes, 1, x.length);
		System.arraycopy(y, 0, pointbytes, 1 + x.length, y.length);

		return pointbytes;
	}

}
