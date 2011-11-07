package de.tsenger.androsmex.tools;
import java.io.ByteArrayOutputStream;

/********************************************************************
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                   Algorithm AES-CMAC                              +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                                                                   +
+   Input    : K    ( 128-bit key )                                 +
+            : M    ( message to be authenticated )                 +
+            : len  ( length of the message in octets )             +
+   Output   : T    ( message authentication code )                 +
+                                                                   +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+   Constants: const_Zero is 0x00000000000000000000000000000000     +
+              const_Bsize is 16                                    +
+                                                                   +
+   Variables: K1, K2 for 128-bit subkeys                           +
+              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
+              M_last is the last block xor-ed with K1 or K2        +
+              n      for number of blocks to be processed          +
+              r      for number of octets of last block            +
+              flag   for denoting if last block is complete or not +
+                                                                   +
+   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
+   Step 2.  n := ceil(len/const_Bsize);                            +
+   Step 3.  if n = 0                                               +
+            then                                                   +
+                 n := 1;                                           +
+                 flag := false;                                    +
+            else                                                   +
+                 if len mod const_Bsize is 0                       +
+                 then flag := true;                                +
+                 else flag := false;                               +
+                                                                   +
+   Step 4.  if flag is true                                        +
+            then M_last := M_n XOR K1;                             +
+            else M_last := padding(M_n) XOR K2;                    +
+   Step 5.  X := const_Zero;                                       +
+   Step 6.  for i := 1 to n-1 do                                   +
+                begin                                              +
+                  Y := X XOR M_i;                                  +
+                  X := AES-128(K,Y);                               +
+                end                                                +
+            Y := M_last XOR X;                                     +
+            T := AES-128(K,Y);                                     +
+   Step 7.  return T;                                              +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
********************************************************************/

/**
 * adapted by Nutrition24 from http://tools.ietf.org/html/rfc4493
 *
 * AES-CMAC with AES-128 bit
 * CMAC    Algorithm described in SP800-38B
 * Author: Junhyuk Song (junhyuk.song@samsung.com)
 *         Jicheol Lee  (jicheol.lee@samsung.com)
 *
 */
public class AESCMac {
	private static byte[] const_Zero = HexString.hexToBuffer("00000000000000000000000000000000");
	private static byte[] const_Rb = HexString.hexToBuffer("00000000000000000000000000000087");
	
	private byte[] contentKey;
	private ByteArrayOutputStream barros;
	
	public AESCMac()
	{
	}
	
	public void doInit(byte[] contentKey)
	{
		this.contentKey = contentKey;
		barros = new ByteArrayOutputStream();
	}
	
	public void doUpdate(byte[] input, int offset, int len)
	{
		barros.write(input, offset, len);
	}

	public void doUpdate(byte[] input)
	{
		barros.write(input, 0, input.length);
	}

	public byte[] doFinal()
	{
		Object[] keys = generateSubKey(contentKey);
		byte[] K1 = (byte[]) keys[0];
		byte[] K2 = (byte[]) keys[1];

		byte[] input = barros.toByteArray();

		int numberOfRounds = (input.length+15) / 16;
		boolean lastBlockComplete;
		
		if (numberOfRounds == 0) {
			numberOfRounds = 1;
			lastBlockComplete = false;
		}
		else {
			if (input.length % 16 == 0) {
				lastBlockComplete = true;
			}
			else {
				lastBlockComplete = false;
			}
		}
		
		byte[] M_last;
		int srcPos = 16 * (numberOfRounds -1);
		
		if (lastBlockComplete) {
			byte[] partInput = new byte[16];
			
			System.arraycopy(input, srcPos, partInput, 0, 16);
			M_last = xor128(partInput, K1);
		}
		else {
			byte[] partInput = new byte[input.length % 16];
			
			System.arraycopy(input, srcPos, partInput, 0, input.length % 16);
			byte[] padded = doPadding(partInput);
			M_last = xor128(padded, K2);
		}
		
		byte[] X = const_Zero.clone();
		byte[] partInput = new byte[16];
		byte[] Y;

		for (int i = 0; i < numberOfRounds - 1; i++) {
			srcPos = 16 * i;
			System.arraycopy(input, srcPos, partInput, 0, 16);

			Y = xor128(partInput, X); /* Y := Mi (+) X */
			X = AESFunc.encryptAES128(Y, contentKey);
		}

		Y = xor128(X, M_last);
		X = AESFunc.encryptAES128(Y, contentKey);

		return X;
	}

	public boolean doVerifyCMAC(byte[] verificationCMAC)
	{
		byte[] cmac = doFinal();

		if (verificationCMAC == null || verificationCMAC.length != cmac.length) {
			return false;
		}
		
		//System.out.println("cmac            : " + Utils.toHexString(cmac));
		//System.out.println("verificationCMAC: " + Utils.toHexString(verificationCMAC));
		
        for (int i=0; i<cmac.length; i++) {
        	if (cmac[i] != verificationCMAC[i]) {
        		return false;
        	}
        }

        return true;
	}
	
	private byte[] doPadding(byte[] input)
	{
		byte[] padded = new byte[16];
		
		for (int j=0; j<16; j++) {
			if (j < input.length) {
				padded[j] = input[j];
			}
			else if (j == input.length) {
				padded[j] = (byte)0x80;
			}
			else {
				padded[j] = (byte)0x00;
			}
		}
		
		return padded;
	}
	
	/**
	   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	   +                    Algorithm Generate_Subkey                      +
	   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	   +                                                                   +
	   +   Input    : K (128-bit key)                                      +
	   +   Output   : K1 (128-bit first subkey)                            +
	   +              K2 (128-bit second subkey)                           +
	   +-------------------------------------------------------------------+
	   +                                                                   +
	   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
	   +              const_Rb   is 0x00000000000000000000000000000087     +
	   +   Variables: L          for output of AES-128 applied to 0^128    +
	   +                                                                   +
	   +   Step 1.  L := AES-128(K, const_Zero);                           +
	   +   Step 2.  if MSB(L) is equal to 0                                +
	   +            then    K1 := L << 1;                                  +
	   +            else    K1 := (L << 1) XOR const_Rb;                   +
	   +   Step 3.  if MSB(K1) is equal to 0                               +
	   +            then    K2 := K1 << 1;                                 +
	   +            else    K2 := (K1 << 1) XOR const_Rb;                  +
	   +   Step 4.  return K1, K2;                                         +
	   +                                                                   +
	   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	**/
	public static Object[] generateSubKey(byte[] key)
	{
		/* Step 1 */
		byte[] L = AESFunc.encryptAES128(const_Zero, key);
		
		/* Step 2 */
		byte[] K1 = null;
		if ( (L[0] & 0x80) == 0 ) { /* If MSB(L) = 0, then K1 = L << 1 */
	          K1 = doLeftShiftOneBit(L);
	      } else {    /* Else K1 = ( L << 1 ) (+) Rb */
	    	  byte[] tmp = doLeftShiftOneBit(L);
	          K1 = xor128(tmp,const_Rb);
	      }

		/* Step 3 */
		byte[] K2 = null;
		if ( (K1[0] & 0x80) == 0 ) {
	          K2 = doLeftShiftOneBit(K1);
	      } else {
	          byte[] tmp = doLeftShiftOneBit(K1);
	          K2 = xor128(tmp,const_Rb);
	      }

		/* Step 4 */
		Object[] result = new Object[2];
		result[0] = K1;
		result[1] = K2;
		return result;
	}
	
	private static byte[] xor128(byte[] input1, byte[] input2)
	{
		byte[] output = new byte[input1.length];
		for (int i=0; i<input1.length; i++) {
			output[i] = (byte)(((int)input1[i] ^(int)input2[i]) & 0xFF);
		}
		return output;
	}
	
	private static byte[] doLeftShiftOneBit(byte[] input)
	{
		byte[] output = new byte[input.length];
		byte overflow = 0;
		
		for (int i=(input.length-1); i>=0; i--) {
			output[i] = (byte)((int)input[i] << 1 & 0xFF);
			output[i] |= overflow;
			overflow = ((input[i] & 0x80) != 0)? (byte)1: (byte)0;
		}
		
		return output;
	}
	
	/**
	public static void main(String[] args)
	throws Exception
	{
		AESCMac cmac = new AESCMac();
		
		byte[] key = new byte[] {
				(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
				(byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
				(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
				(byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
		};
		byte[] M = new byte[] {
				(byte) 0x6b, (byte) 0xc1, (byte) 0xbe, (byte) 0xe2,
				(byte) 0x2e, (byte) 0x40, (byte) 0x9f, (byte) 0x96,
				(byte) 0xe9, (byte) 0x3d, (byte) 0x7e, (byte) 0x11,
				(byte) 0x73, (byte) 0x93, (byte) 0x17, (byte) 0x2a,
				(byte) 0xae, (byte) 0x2d, (byte) 0x8a, (byte) 0x57,
				(byte) 0x1e, (byte) 0x03, (byte) 0xac, (byte) 0x9c,
				(byte) 0x9e, (byte) 0xb7, (byte) 0x6f, (byte) 0xac,
				(byte) 0x45, (byte) 0xaf, (byte) 0x8e, (byte) 0x51,
				(byte) 0x30, (byte) 0xc8, (byte) 0x1c, (byte) 0x46,
				(byte) 0xa3, (byte) 0x5c, (byte) 0xe4, (byte) 0x11,
				(byte) 0xe5, (byte) 0xfb, (byte) 0xc1, (byte) 0x19,
				(byte) 0x1a, (byte) 0x0a, (byte) 0x52, (byte) 0xef,
				(byte) 0xf6, (byte) 0x9f, (byte) 0x24, (byte) 0x45,
				(byte) 0xdf, (byte) 0x4f, (byte) 0x9b, (byte) 0x17,
				(byte) 0xad, (byte) 0x2b, (byte) 0x41, (byte) 0x7b,
				(byte) 0xe6, (byte) 0x6c, (byte) 0x37, (byte) 0x10
		};
		
		byte[] T;
		
		System.out.println("K: " + Utils.toHexString(key));
		System.out.println("Subkey generation");
		
		byte[] L = AESFunc.encryptAES128(const_Zero, key);
		
		System.out.println("AES_128(key,0) : " + Utils.toHexString(L));
		
		Object[] keys = generateSubKey(key);
		byte[] K1 = (byte[]) keys[0];
		byte[] K2 = (byte[]) keys[1];
		
		System.out.println("K1: " + Utils.toHexString(K1));
		System.out.println("K2: " + Utils.toHexString(K2));

		System.out.println();
		
		System.out.println("Example 1: len = 0");
		System.out.println("M <empty string>");
		cmac.doInit(key);
		T = cmac.doFinal();
		System.out.println("AES_CMAC: " + Utils.toHexString(T));
		
		System.out.println("Example 2: len = 16");
		cmac.doInit(key);
		cmac.doUpdate(M, 0, 16);
		T = cmac.doFinal();
		System.out.println("M " + Utils.toHexString(M).substring(0, 32));
		System.out.println("AES_CMAC: " + Utils.toHexString(T));

		System.out.println("Example 3: len = 40");
		cmac.doInit(key);
		cmac.doUpdate(M, 0, 40);
		T = cmac.doFinal();
		System.out.println("M " + Utils.toHexString(M).substring(0, 80));
		System.out.println("AES_CMAC: " + Utils.toHexString(T));

		System.out.println("Example 4: len = 64");
		cmac.doInit(key);
		cmac.doUpdate(M, 0, 64);
		T = cmac.doFinal();
		System.out.println("M " + Utils.toHexString(M).substring(0, 128));
		System.out.println("AES_CMAC: " + Utils.toHexString(T));
	}
	**/
}