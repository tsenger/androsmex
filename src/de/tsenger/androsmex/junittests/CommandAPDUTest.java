/**
 * 
 */
package de.tsenger.androsmex.junittests;

import java.util.Arrays;

import de.tsenger.androsmex.CommandAPDU;
import junit.framework.TestCase;

/**
 * @author tobi
 *
 */
public class CommandAPDUTest extends TestCase {
	
	private byte[] header = {(byte)0x00, (byte)0xA4, (byte)0x01, (byte)0x02};
	private byte lc = 0x05;
	private byte[] data = new byte[] {(byte)0xF1, (byte)0xF2, (byte)0xF3, (byte)0xF4, (byte)0xF5};
	private byte le = (byte)0xFF;
	private byte[] lc_extended = new byte[] {(byte)0x00, (byte)0x00, (byte)0x05};
	
	CommandAPDU capdu = null;

	/**
	 * @param name
	 */
	public CommandAPDUTest(String name) {
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
		capdu = new CommandAPDU(100);
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.CommandAPDU#CommandAPDU(int)}.
	 */
	public void testCommandAPDU() {
		assertTrue(capdu!=null);
		assertTrue(capdu.getBytes()!=null);
	}
	

	/**
	 * Test method for {@link de.tsenger.androsmex.CommandAPDU#append(byte[])}.
	 */
	public void testAppendByteArray() {
		capdu.append(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
		assertTrue(capdu.getBytes().length==5);
		assertTrue(capdu.getBytes()[0]==0x01);
		assertTrue(capdu.getBytes()[1]==0x02);
		assertTrue(capdu.getBytes()[2]==0x03);
		assertTrue(capdu.getBytes()[3]==0x04);
		assertTrue(capdu.getBytes()[4]==0x05);
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.CommandAPDU#append(byte)}.
	 */
	public void testAppendByte() {
		capdu.append(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
		capdu.append((byte)0x06);
		assertTrue(capdu.getBytes().length==6);
		assertTrue(capdu.getBytes()[0]==0x01);
		assertTrue(capdu.getBytes()[1]==0x02);
		assertTrue(capdu.getBytes()[2]==0x03);
		assertTrue(capdu.getBytes()[3]==0x04);
		assertTrue(capdu.getBytes()[4]==0x05);
		assertTrue(capdu.getBytes()[5]==0x06);
		
	}

	/**
	 * Test method for {@link de.tsenger.androsmex.CommandAPDU#getBytes()}.
	 */
	public void testGetBytes() {
		capdu.append((byte)0xFF);
		assertTrue(capdu.getBytes().length==1);
		assertTrue(capdu.getBytes()[0]==(byte)0xFF);
	}
	
	public void testCase1APDU() {
		capdu.append(header);
		assertTrue(capdu.getAPDUStructure()==capdu.CASE1_CAPDU);
		assertTrue(Arrays.equals(capdu.header(), header));
	}
	
	public void testCase2SAPDU() {
		capdu.append(header);
		capdu.append(le);
		assertTrue(capdu.getAPDUStructure()==capdu.CASE2S_CAPDU);
		assertTrue(Arrays.equals(capdu.header(), header));
		assertTrue(capdu.le()==le);
	}
	
	public void testCase3SAPDU() {
		capdu.append(header);
		capdu.append(lc);
		capdu.append(data);
		assertTrue(capdu.getAPDUStructure()==capdu.CASE3S_CAPDU);
		assertTrue(Arrays.equals(capdu.header(), header));
		assertTrue(capdu.lc()==lc);
		assertTrue(Arrays.equals(capdu.data(), data));
	}
	
	public void testCase4SAPDU() {
		capdu.append(header);
		capdu.append(lc);
		capdu.append(data);
		capdu.append(le);
		assertTrue(capdu.getAPDUStructure()==capdu.CASE4S_CAPDU);
		assertTrue(Arrays.equals(capdu.header(), header));
		assertTrue(capdu.lc()==lc);
		assertTrue(Arrays.equals(capdu.data(), data));
		assertTrue(capdu.le()==le);
	}

}
