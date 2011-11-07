package de.tsenger.pace;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Random;

import ext.org.bouncycastle.crypto.tls.NamedCurve;
import ext.org.bouncycastle.math.ec.ECCurve;

import de.flexiprovider.api.KeyAgreement;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.ellipticcurves.ScalarMult;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.common.util.DefaultPRNG;
import de.flexiprovider.ec.parameters.CurveRegistry;
import de.tsenger.androsmex.tools.HexString;

public class PACE_ECDH_DomainParameter {
	
	private static String z = "CE834CDE69FFBB1D1EB21585CD709F18"; //encrypted nonce
	private static String s = "7D98C00FC6C9E9543BBF94A87073A123"; //decrypted nonce
	private static String string_random = new String("752287F5B02DE3C4BC3E17945118C51B23C97278E4CD748048AC56BA5BDC3D46");
	private static String picc_PK = new String("9CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A");
	
	public byte[] start(String s_String) {	
		
		CurveRegistry.BrainpoolP256r1 brainpoolP256r1 = new CurveRegistry.BrainpoolP256r1();
		
		EllipticCurveGFP curve = (EllipticCurveGFP) brainpoolP256r1.getE();
		System.out.println("Kurve: "+curve.toString());
		PointGFP point_G = (PointGFP) brainpoolP256r1.getG();
		
		
//		DefaultPRNG randomGenerator = new DefaultPRNG();
		
		FlexiBigInt random_x1 = new FlexiBigInt(string_random,16);
//		FlexiBigInt random_x1 = new FlexiBigInt(256, randomGenerator);
		
		System.out.println("SK:\n"+random_x1.toString(16));
		PointGFP X1 = (PointGFP) ScalarMult.multiply4(random_x1, point_G);
		//X1 wird zur Karte gesendet. X1 müsste PK_PCD sein...
		System.out.println("X1:\n"+X1.toString());
		
		//Antwort der Karte
		FlexiBigInt picc_x = new FlexiBigInt("9CFCF7582AC986D0DD52FA53123414C3E1B96B4D00ABA8E574679B70EFB5BC3B",16);
		FlexiBigInt picc_y = new FlexiBigInt("45D2F13729CC2AE178E7E241B443213533B77DBB44649A815DDC4A2384BA422A",16);
		GFPElement mx = new GFPElement(picc_x, curve.getQ());
		GFPElement my = new GFPElement(picc_y, curve.getQ());
		PointGFP Y1 = new PointGFP(mx,my,curve);
		System.out.println("Y1:\n"+Y1.toString());
		
		//shared secret
		
		PointGFP P = (PointGFP) ScalarMult.multiply4(random_x1, Y1);
		System.out.println("P:\n"+P.toString());
		
		//Berechne G_Strich
		FlexiBigInt ms = new FlexiBigInt(s,16);
		System.out.println("s:\n"+ms.toString(16));
		PointGFP g1 = (PointGFP) ScalarMult.multiply4(ms, point_G);
		PointGFP g_strich = (PointGFP) g1.add(P);
		System.out.println("G_Strich:\n"+g_strich.toString());
		
		
		
		//Zweiter SK_PCD
		FlexiBigInt random_x2 = new FlexiBigInt("9D9A32DF93A57CCE33CA3CDD3457E33A976F293546C73550F397259C93BE0120",16);
		System.out.println("SK2:\n"+random_x2.toString(16));
		PointGFP X2 = (PointGFP) ScalarMult.multiply4(random_x2, g_strich);
		System.out.println("G_Strich:\n"+g_strich.toString());
		System.out.println("X2:\n"+X2.toString());//<<< zweiter PK_PCD
		
		
		//Antwort der Karte
		FlexiBigInt picc_x2 = new FlexiBigInt("282cf38073036afac216af135bd994da0c357f10bd4c34afea1042b2eb0fd680",16);
		FlexiBigInt picc_y2 = new FlexiBigInt("4df3658b835ac2e7133f13691184542bb50b109963a4662abdc08b9763af4b5b",16);
		GFPElement mx2 = new GFPElement(picc_x2, curve.getQ());
		GFPElement my2 = new GFPElement(picc_y2, curve.getQ());
		PointGFP Y2 = new PointGFP(mx2,my2,curve);
		System.out.println("Y2:\n"+Y2.toString());
		
		
		//shared secret
		PointGFP K = (PointGFP) ScalarMult.multiply4(random_x2, Y2);
		System.out.println("K:\n"+K.toString());
		
		return K.getX().toByteArray();
	}

}
