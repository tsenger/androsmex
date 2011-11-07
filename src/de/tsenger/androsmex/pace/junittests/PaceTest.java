package de.tsenger.androsmex.pace.junittests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.ec.parameters.CurveRegistry;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGFP;
import de.tsenger.androsmex.pace.PACEOID;
import de.tsenger.androsmex.pace.Pace_old;
import de.tsenger.androsmex.pace.paceASN1objects.SecurityInfos;
import de.tsenger.androsmex.tools.HexString;
import junit.framework.TestCase;

public class PaceTest extends TestCase {
	
	SecurityInfos efCardAccess = null;
	ASN1ObjectIdentifier protocol = null;
	CurveParamsGFP cP = null;
	Pace_old paceObject = null;
	private String z = "CE834CDE69FFBB1D1EB21585CD709F18"; //encrypted nonce

	public PaceTest(String name) {
		super(name);
	}

	protected void setUp() throws Exception {
		super.setUp();
		efCardAccess = new SecurityInfos();
        try {
            efCardAccess.decode(readBinaryFile("/home/senger/Desktop/Transport/EF_CardAccess_001.bin"));
        }
        catch (ASN1Exception ex) {} 
        catch (IOException ex) {}
        
        decodePACEparameters();
        
        paceObject = new Pace_old(cP);
	}

	public void testgetX1() {		
		PointGFP X1 = paceObject.getX1("1234", HexString.hexToBuffer(z));
		assertTrue(true);
	}
	
	public void testgetK() {
		PointGFP X1 = paceObject.getX1("1234", HexString.hexToBuffer(z));
		PointGFP X2 = null;
		try {
			X2 = paceObject.getX2(getY1());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] K = paceObject.getK(getY2());
		assertTrue(true);
	}
	
	private PointGFP getY1() {
		FlexiBigInt picc_x = new FlexiBigInt("9CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B",16);
		FlexiBigInt picc_y = new FlexiBigInt("45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A",16);
		EllipticCurveGFP curve = (EllipticCurveGFP) cP.getE();
		GFPElement mx = new GFPElement(picc_x, curve.getQ());
		GFPElement my = new GFPElement(picc_y, curve.getQ());
		PointGFP Y1 = new PointGFP(mx,my,curve);
		System.out.println("Y1 PointGFP:\n"+Y1.toString());
		System.out.println("Y1 Q:\n"+curve.getQ().toString(16));
		return Y1;
	}
	private PointGFP getY2() {
		FlexiBigInt picc_x2 = new FlexiBigInt("282cf38073036afac216af135bd994da0c357f10bd4c34afea1042b2eb0fd680",16);
		FlexiBigInt picc_y2 = new FlexiBigInt("4df3658b835ac2e7133f13691184542bb50b109963a4662abdc08b9763af4b5b",16);
		EllipticCurveGFP curve = (EllipticCurveGFP) cP.getE();
		GFPElement mx2 = new GFPElement(picc_x2, curve.getQ());
		GFPElement my2 = new GFPElement(picc_y2, curve.getQ());
		PointGFP Y2 = new PointGFP(mx2,my2,curve);
		System.out.println("Y2 PointGFP:\n"+Y2.toString());
		System.out.println("Y2 Q:\n"+curve.getQ().toString(16));
		return Y2;
	}
	
	private void decodePACEparameters() {
		if (efCardAccess==null) return;
		protocol = efCardAccess.getPACEInfo().getProtocol();
		if (protocol.equals(PACEOID.id_PACE_ECDH_GM_AES_CBC_CMAC_128)) {
			//AES_128
		}
		int parameterId = efCardAccess.getPACEInfo().getParameterId();
		
		if (parameterId>7&&parameterId<32) { 
			// standardized domain parameters
			
			if (parameterId==11) {
				
				CurveRegistry.BrainpoolP224r1 brainpoolP224r1 = new CurveRegistry.BrainpoolP224r1();
				cP = brainpoolP224r1;
			}
			if (parameterId==13) {
				
				CurveRegistry.BrainpoolP256r1 brainpoolP256r1 = new CurveRegistry.BrainpoolP256r1();
				cP = brainpoolP256r1;
			}
		}
		else {
			// proprietary domain parameters
		
			CurveRegistry.BrainpoolP256r1 brainpoolP256r1 = new CurveRegistry.BrainpoolP256r1();
			cP = brainpoolP256r1;
		}
	}
	
	private static byte[] readBinaryFile(String filename)
    {
        FileInputStream in = null;

        File efCardAccessFile = new File(filename);
        byte buffer[] = new byte[(int)efCardAccessFile.length()];

        try
        {
            in = new FileInputStream(efCardAccessFile);
            in.read(buffer, 0, buffer.length);
        }
        catch (FileNotFoundException ex)
        {
            
        }
        catch (IOException ex) {}

        return buffer;
    }

}
