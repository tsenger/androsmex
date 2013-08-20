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
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;

import de.tsenger.androsmex.tools.HexString;

/**
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */
public class FileID extends ASN1Encodable{

	private DEROctetString fid = null;
	private DEROctetString sfid = null;

	public FileID(DERSequence seq) {
		fid = (DEROctetString) seq.getObjectAt(0);
		if (seq.size() > 1) {
			sfid = (DEROctetString) seq.getObjectAt(1);
		}
	}

	public byte[] getFID() {
		return fid.getOctets();
	}

	public byte getSFID() {
		if (sfid != null)
			return (sfid.getOctets()[0]);
		else
			return -1; // optionales Feld sfid ist nicht vorhanden
	}

	@Override
	public String toString() {
		return "FileID \n\tFID: " + HexString.bufferToHex(getFID())
				+ "\n\tSFID: " + getSFID() + "\n";
	}

	/**
	 * The definition of FileID is
     * <pre>
     * FileID ::= SEQUENCE {
     *      fid		OCTET STRING (SIZE(2)),
     *      sfid	OCTET STRING (SIZE(1)) OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(fid);
		if (sfid!=null) v.add(sfid);
		
		return new DERSequence(v);
	}

}
