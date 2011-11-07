package de.tsenger.pace.junittests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import de.tsenger.pace.paceASN1objects.SecurityInfos_bc;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;

import junit.framework.TestCase;

public class SecurityInfos_bcTest extends TestCase {
	
	SecurityInfos_bc si = null;

	protected void setUp() throws Exception {
		si = new SecurityInfos_bc();
		super.setUp();
	}

	public void testDecode() {
		try {
			si.decode(readBinaryFile("/home/senger/Desktop/Transport/2011-07-13_X00301950_EF.CardAccess.bin"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		DERObjectIdentifier oid = (DERObjectIdentifier) si.getCIL().getObjectAt(0);
		System.out.println(oid.getId());
		assertTrue(si.getPACEInfo()!=null);
	}
	
	private byte[] readBinaryFile(String filename)
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
