package de.tsenger.androsmex.pace.paceASN1objects;

import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.asn1.DERSequence;
import ext.org.bouncycastle.asn1.DERInteger;

public class PaceInfo_bc {
	
	private DERObjectIdentifier protocol = null;
	private int version = 0;
	private int parameterId = 0;

	public PaceInfo_bc(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		DERInteger v = (DERInteger)seq.getObjectAt(1);
		version = v.getValue().intValue();
		if (seq.size()>2) {
			DERInteger p = (DERInteger)seq.getObjectAt(2);
			parameterId = p.getValue().intValue();
		}
	}
	
	public PaceInfo_bc(DERObjectIdentifier protocol, int version, int parameterId) {
		this.protocol = protocol;
		this.version = version;
		this.parameterId = parameterId;
	}
	
	public DERObjectIdentifier getProtocol() {
		return protocol;
	}
	
	public int getVersion() {
		return version;
	}
	
	public int getParameterId() {
		return parameterId;
	}
}
