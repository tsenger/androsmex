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

import java.io.IOException;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class PrivilegedTerminalInfo extends ASN1Encodable{

	private DERObjectIdentifier protocol = null;
	private SecurityInfos secinfos = null;

	public PrivilegedTerminalInfo(DERSequence seq) throws IOException {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);

		DERSet derSet = (DERSet) seq.getObjectAt(1);

		SecurityInfos si = new SecurityInfos();
		si.decode(derSet.getEncoded());

		secinfos = (si);
	}

	public String getProtocolOID() {
		return protocol.getId();
	}

	public SecurityInfos getSecurityInfos() {
		return secinfos;
	}

	@Override
	public String toString() {
		return "PrivilegedTerminalInfo\n\tOID: " + getProtocolOID()
				+ "\n\tSecurityInfos: " + getSecurityInfos() + "\n";
	}

	/**
	 * The definition of PrivilegedTerminalInfo is
     * <pre>
     * PrivilegedTerminalInfo ::= SEQUENCE {
     *      protocol				OBJECT IDENTIFIER(id-PT),
     *      privilegedTerminalInfos	SecurityInfos
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {

		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(secinfos);
		
		return new DERSequence(v);
	}

}
