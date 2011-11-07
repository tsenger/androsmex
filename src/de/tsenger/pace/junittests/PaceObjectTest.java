package de.tsenger.pace.junittests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;

import junit.framework.TestCase;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGFP;
import de.flexiprovider.ec.parameters.CurveRegistry;
import de.tsenger.androsmex.tools.HexString;
import de.tsenger.pace.PACEOID;
import de.tsenger.pace.PACE_ECDH_DomainParameter;
import de.tsenger.pace.Pace_old;
import de.tsenger.pace.paceASN1objects.SecurityInfos;

public class PaceObjectTest extends TestCase {
	
	Pace_old po = null;
	PACE_ECDH_DomainParameter dp = null;
	SecurityInfos efCardAccess = null;
	private ASN1ObjectIdentifier protocol = null; 
	
	private CurveParamsGFP cP = null;
	
	private String z = "CE834CDE69FFBB1D1EB21585CD709F18"; //encrypted nonce
	private String s = "7D98C00FC6C9E9543BBF94A87073A123"; //decrypted nonce
	
	FlexiBigInt picc_x = new FlexiBigInt("9CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B",16);
	FlexiBigInt picc_y = new FlexiBigInt("45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A",16);
	
	FlexiBigInt picc_x2 = new FlexiBigInt("282cf38073036afac216af135bd994da0c357f10bd4c34afea1042b2eb0fd680",16);
	FlexiBigInt picc_y2 = new FlexiBigInt("4df3658b835ac2e7133f13691184542bb50b109963a4662abdc08b9763af4b5b",16);
	
	
		
	// r = a nonce
	byte[] r;
	
	// c = a 32-bit, big endian integer counter 
	// (byte)0x00000001 for en-/decoding
	// (byte)0x00000002 for MAC (checksum)
	// (byte)0x00000003 for deriving encryption keys from a password
	byte[] c = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03};
	byte[] c1 = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01};
	byte[] c2 = new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02};

	protected void setUp() throws Exception {
		super.setUp();
		efCardAccess = new SecurityInfos();
        try {
            efCardAccess.decode(readBinaryFile("/home/senger/Desktop/Transport/EF_CardAccess_001.bin"));
        } 
        catch (ASN1Exception ex) {} 
        catch (IOException ex) {}

        System.out.println(efCardAccess);
        
	}

	public void testgetX1() {
		decodePACEparameters();
		try {
			po = new Pace_old(cP);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		PointGFP X1 = po.getX1("1234", HexString.hexToBuffer(z));
		System.out.println(X1.toString());
		assertTrue(true);
	}
	
	
	/**
	 * Ermittelt anhand des EF.CardAccess die f�r PACE ben�tigten Domain Parameter. 
	 * Diese Methode ermittelt die Kurve und den Punkt G.
	 */
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
