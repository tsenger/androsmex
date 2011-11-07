package de.tsenger.pace.junittests;

import de.tsenger.pace.PACE_ECDH_DomainParameter;
import junit.framework.TestCase;

public class PACE_ECDH_DomainParameterTest extends TestCase {
	
	PACE_ECDH_DomainParameter dp1 = null;

	protected void setUp() throws Exception {
		super.setUp();
		dp1= new PACE_ECDH_DomainParameter();
	}

	public void testStart() {
		dp1.start("ddd");
		assertTrue(true);
	}

}
