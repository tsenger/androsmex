/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.androsmex.asn1;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PaceDomainParameterInfo extends ASN1Encodable {

	private DERObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private DERInteger parameterId = null;

	public PaceDomainParameterInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

		if (seq.size() > 2) {
			parameterId = (DERInteger) seq.getObjectAt(2);
		}
	}

	public DERObjectIdentifier getProtocol() {
		return protocol;
	}

	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	public int getParameterId() {
		if (parameterId == null)
			return -1; // optionales Feld parameterId nicht vorhanden
		else
			return parameterId.getValue().intValue();
	}

	@Override
	public String toString() {
		return "PaceDomainParameterInfo\n\tOID: " + getProtocol()
				+ "\n\tDomainParameter: \n\t\t"
				+ getDomainParameter().getAlgorithm() + "\n\t\t"
				+ getDomainParameter().getParameters() + "\n\tParameterId: "
				+ getParameterId() + "\n";
	}

	/**
	 * The definition of PaceDomainParameterInfo is
     * <pre>
     * PaceDomainParameterInfo ::= SEQUENCE {
     *      protocol		OBJECT IDENTIFIER(,
     *      				id-PACE-DH-GM |
     *      				id-PACE-ECDH-GM |
     *      				id-PACE-DH-IM |
     *      				id-PACE-ECDH-IM),
     *      domainParameter	AlgorithmIdentifier,
     *      parameterId		INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(domainParameter);
		if (parameterId!=null) v.add(parameterId);
		
		return new DERSequence(v);
	}
}
