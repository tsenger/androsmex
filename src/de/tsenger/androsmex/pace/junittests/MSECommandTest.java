package de.tsenger.androsmex.pace.junittests;

import java.util.Arrays;

import ext.org.bouncycastle.asn1.DERObjectIdentifier;

import junit.framework.TestCase;
import de.tsenger.androsmex.pace.MSECommand;
import de.tsenger.androsmex.pace.PACEOID;
import de.tsenger.androsmex.pace.paceASN1objects.CertificateHolderAuthorizationTemplate;
import de.tsenger.androsmex.tools.HexString;

public class MSECommandTest extends TestCase {
	
	private byte[] mse1 = HexString.hexToBuffer("0022c1a424800a04007f000702020402028301027f4c12060904007f00070301020253053FFFFFFFF7");
	private byte[] mse2 = HexString.hexToBuffer("0022c1a424800a04007f000702020402028301037f4c12060904007f00070301020253053FFFFFFFF7");

	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testGetTESTPace() {
		MSECommand mse = new MSECommand(200);
		mse.setAT(MSECommand.setAT_PACE);
		mse.setCMR(PACEOID.id_PACE_ECDH_GM_AES_CBC_CMAC_128);
		mse.setKeyReference(MSECommand.KeyReference_CAN);
		//mse.setPrivateKeyReference((byte)0xD);
		mse.setCHAT(getChat());
		byte[] mseCommand = mse.getBytes();
		System.out.println(HexString.bufferToHex(mseCommand));
		assertTrue(Arrays.equals(mseCommand, mse1));
	}
	
	public void testGetTESTPace2() {
		MSECommand mse = new MSECommand(200);
		mse.setAT(MSECommand.setAT_PACE);
		mse.setCMR(PACEOID.id_PACE_ECDH_GM_AES_CBC_CMAC_128);
		mse.setKeyReference(MSECommand.KeyReference_PIN);
		mse.setCHAT(getChat());
		byte[] mseCommand = mse.getBytes();
		System.out.println(HexString.bufferToHex(mseCommand));
		assertTrue(Arrays.equals(mseCommand, mse2));
	}
	
	private CertificateHolderAuthorizationTemplate getChat() {
		DERObjectIdentifier id_AT = PACEOID.id_AT;
		CertificateHolderAuthorizationTemplate chat = new CertificateHolderAuthorizationTemplate(id_AT);
		chat.setAuthorization(new byte[]{(byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xF7});
		return chat;
	}

}
