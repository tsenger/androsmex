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
public class ChipAuthenticationDomainParameterInfo extends ASN1Encodable{

	private DERObjectIdentifier protocol = null;
	private AlgorithmIdentifier domainParameter = null;
	private DERInteger keyId = null;

	/**
	 * @param derSequence
	 */
	public ChipAuthenticationDomainParameterInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		domainParameter = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

		if (seq.size() > 2) {
			keyId = (DERInteger) seq.getObjectAt(2);
		}
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public AlgorithmIdentifier getDomainParameter() {
		return domainParameter;
	}

	public int getKeyId() {
		if (keyId == null)
			return -1; // optionales Feld keyId nicht vorhanden
		else
			return keyId.getValue().intValue();
	}

	@Override
	public String toString() {
		return "ChipAuthenticationDomainParameterInfo \n\tOID: "
				+ getProtocolOID() + "\n\tDomainParameter: \n\t\t"
				+ getDomainParameter().getAlgorithm() + "\n\t\t"
				+ getDomainParameter().getParameters() + "\n\tKeyID "
				+ getKeyId() + "\n";
	}

	/**
	 * The definition of ChipAuthenticationDomainParameterInfo is
     * <pre>
     * ChipAuthenticationDomainParameterInfo ::= SEQUENCE {
     *      protocol   			OBJECT IDENTIFIER(id-CA-DH | id-CA-ECDH),
     *      domainParameter		AlgorithmIdentifier,
     *      keyID				INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(domainParameter); 
		if (keyId!=null) v.add(keyId);
		
		return new DERSequence(v);
	}

}
