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

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class TerminalAuthenticationInfo extends ASN1Encodable{

	private DERObjectIdentifier protocol = null;
	private DERInteger version = null;
	private DERSequence fileID = null;

	/**
	 * @param derSequence
	 */
	public TerminalAuthenticationInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		version = (DERInteger) seq.getObjectAt(1);
		if (seq.size() > 2) {
			fileID = (DERSequence) seq.getObjectAt(2);
		}
		if (version.getValue().intValue() == 2 && fileID != null)
			throw new IllegalArgumentException("FileID MUST NOT be used for version 2!");
	}

	public String getProtocolOID() {
		return protocol.toString();
	}

	public int getVersion() {
		return version.getValue().intValue();
	}

	public FileID getEFCVCA() {
		if (fileID == null)
			return null; // optionales Feld FileID nicht vorhanden.
		else
			return new FileID(fileID);
	}

	@Override
	public String toString() {
		return "TerminalAuthenticationInfo\n\tOID: " + getProtocolOID()
				+ "\n\tVersion: " + getVersion() + "\n\tEF.CVCA: "
				+ getEFCVCA() + "\n";
	}

	/**
	 * The definition of TerminalAuthenticationInfo is
     * <pre>
     * TerminalAuthenticationInfo ::= SEQUENCE {
     *      protocol	OBJECT IDENTIFIER(id-TA),
     *      version		INTEGER, -- MUST be 1 or 2
     *      efCVCA		FileID OPTIONAL -- MUST NOT be used for version 2
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(protocol);
		v.add(version);
		if (fileID!=null) v.add(fileID);
		
		return new DERSequence(v);
	}

}
