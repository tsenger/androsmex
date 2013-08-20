/**
 * 
 */
package de.tsenger.androsmex.pace;

import static de.tsenger.androsmex.tools.Converter.bigIntToByteArray;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.spongycastle.crypto.params.DHParameters;


/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class PaceDH extends Pace {
	
	private final SecureRandom randomGenerator = new SecureRandom();
	private BigInteger g = null;
	private BigInteger g_strich = null;
	private BigInteger p = null;
	
	private BigInteger PCD_SK_x1 = null;
	private BigInteger PCD_PK_X1 = null;
	
	private BigInteger PCD_SK_x2 = null;
	private BigInteger PCD_PK_X2 = null;
	
	private BigInteger PICC_PK_Y1 = null;
	private BigInteger PICC_PK_Y2 = null;
	
	private BigInteger SharedSecret_P = null;
	private BigInteger SharedSecret_K = null;

	public PaceDH(DHParameters dhParameters) {
		g = dhParameters.getG();
		p = dhParameters.getP();
		Random rnd = new Random();
		randomGenerator.setSeed(rnd.nextLong());
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.pace.Pace#getX1()
	 */
	@Override
	public byte[] getX1(byte[] s) {
		nonce_s = s.clone();
		byte[] x1 = new byte[g.bitLength()/8];
		randomGenerator.nextBytes(x1);
		PCD_SK_x1 = new BigInteger(1, x1);
//		PCD_SK_x1 = new BigInteger("24C3C0E0A3280ECB943345D9DC2A7B72" +
//				"539FDA6FFDF99AB7B6CDDDD1BE425AF3" +
//				"D02C4ED0CDD73EBB4B2EDF8C07FB3A35" +
//				"903F72B84F3771F4EBFB49520D61A8F7" +
//				"C7FB8C9E2ABC24BF4FF9D8DDF381A193" +
//				"80C85B623AB02ACBF6D220F512BF4065" +
//				"8322AD209AC0BF9E6F8DB602D5197D25" +
//				"2BF6D148510CA1B740AF0F99F33CA5F1",16);
		PCD_PK_X1 = g.modPow(PCD_SK_x1, p);
		return bigIntToByteArray(PCD_PK_X1);
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.pace.Pace#getX2(byte[])
	 */
	@Override
	public byte[] getX2(byte[] Y1) {
		PICC_PK_Y1 = new BigInteger(1, Y1);
		SharedSecret_P = PICC_PK_Y1.modPow(PCD_SK_x1, p);
		sharedSecret_P = SharedSecret_P.abs().toByteArray();
		g_strich = g.modPow(new BigInteger(1, nonce_s),p).multiply(SharedSecret_P).mod(p);
		byte[] x2 = new byte[g.bitLength()/8];
		randomGenerator.nextBytes(x2);
		PCD_SK_x2 = new BigInteger(1, x2);
//		PCD_SK_x2 = new BigInteger("4BD0E54740F9A028E6A515BFDAF96784" +
//				"8C4F5F5FFF65AA0915947FFD1A0DF2FA" +
//				"6981271BC905F3551457B7E03AC3B806" +
//				"6DE4AA406C1171FB43DD939C4BA16175" +
//				"103BA3DEE16419AA248118F90CC36A3D" +
//				"6F4C373652E0C3CCE7F0F1D0C5425B36" +
//				"00F0F0D6A67F004C8BBA33F2B4733C72" +
//				"52445C1DFC4F1107203F71D2EFB28161",16);
		PCD_PK_X2 = g_strich.modPow(PCD_SK_x2, p);
		return bigIntToByteArray(PCD_PK_X2);
	}

	/* (non-Javadoc)
	 * @see de.tsenger.animamea.pace.Pace#getK(byte[])
	 */
	@Override
	public byte[] getSharedSecret_K(byte[] Y2) {
		PICC_PK_Y2 = new BigInteger(1, Y2);
		SharedSecret_K = PICC_PK_Y2.modPow(PCD_SK_x2, p);
		sharedSecret_K = bigIntToByteArray(SharedSecret_K);
		return sharedSecret_K;
	}


}
