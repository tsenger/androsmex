/**
 * 
 */
package de.tsenger.androsmex.junittests;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.tsenger.androsmex.bac.BACFunctions;
import de.tsenger.androsmex.tools.HexString;
import junit.framework.TestCase;

/**
 * @author senger
 *
 */
public class BACFunctionsTest extends TestCase {
	
	BACFunctions bacf = null;

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.bac.BACFunctions#BACFunctions(java.lang.String, byte[])}.
	 */
	public void testBACFunctions() {
		bacf = new BACFunctions("L898902C<3UTO6908061F9406236ZE184226B<<<<<14",new byte[] {(byte)0x46, (byte)0x08, (byte)0xF9, (byte)0x19, (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12});
		assertTrue(bacf!=null);
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.bac.BACFunctions#getMutualAuthenticationCommand()}.
	 * @throws InvalidAlgorithmParameterException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void testGetMutualAuthenticationCommand() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		bacf = new BACFunctions("L898902C<3UTO6908061F9406236ZE184226B<<<<<14",new byte[] {(byte)0x46, (byte)0x08, (byte)0xF9, (byte)0x19, (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12});
		byte[] mu_data = bacf.getMutualAuthenticationCommand();
		byte [] expected_data = new byte[] {(byte)0x72, (byte)0xC2, (byte)0x9C, (byte)0x23, (byte)0x71, (byte)0xCC, (byte)0x9B, (byte)0xDB,
				(byte)0x65, (byte)0xB7, (byte)0x79, (byte)0xB8, (byte)0xE8, (byte)0xD3, (byte)0x7B, (byte)0x29, (byte)0xEC, (byte)0xC1, (byte)0x54, (byte)0xAA,
				(byte)0x56, (byte)0xA8, (byte)0x79, (byte)0x9F, (byte)0xAE, (byte)0x2F, (byte)0x49, (byte)0x8F, (byte)0x76, (byte)0xED, (byte)0x92, (byte)0xF2,
				(byte)0x5F, (byte)0x14, (byte)0x48, (byte)0xEE, (byte)0xA8, (byte)0xAD, (byte)0x90, (byte)0xA7
		};
		System.out.println(HexString.bufferToHex(mu_data));
		assertTrue(Arrays.equals(mu_data, expected_data));
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.bac.BACFunctions#establishBAC(byte[])}.
	 * @throws InvalidAlgorithmParameterException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public void testEstablishBAC() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		bacf = new BACFunctions("L898902C<3UTO6908061F9406236ZE184226B<<<<<14",new byte[] {(byte)0x46, (byte)0x08, (byte)0xF9, (byte)0x19, (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12});
		byte[] mu_data = bacf.getMutualAuthenticationCommand();
		byte[] mu_response = {(byte)0x46, (byte)0xB9, (byte)0x34, (byte)0x2A, (byte)0x41, (byte)0x39, (byte)0x6C, (byte)0xD7,
		        (byte)0x38, (byte)0x6B, (byte)0xF5, (byte)0x80, (byte)0x31, (byte)0x04, (byte)0xD7, (byte)0xCE,
		        (byte)0xDC, (byte)0x12, (byte)0x2B, (byte)0x91, (byte)0x32, (byte)0x13, (byte)0x9B, (byte)0xAF,
		        (byte)0x2E, (byte)0xED, (byte)0xC9, (byte)0x4E, (byte)0xE1, (byte)0x78, (byte)0x53, (byte)0x4F,
		        (byte)0x2F, (byte)0x2D, (byte)0x23, (byte)0x5D, (byte)0x07, (byte)0x4D, (byte)0x74, (byte)0x49};
		assertTrue(bacf.establishBAC(mu_response)!=null);
	}

}
