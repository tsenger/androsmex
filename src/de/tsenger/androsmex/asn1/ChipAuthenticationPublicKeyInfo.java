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

import de.tsenger.androsmex.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 * The ChipAuthenticationPublicKeyInfo object.
 * <pre>
 * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
 *   protocol						OBJECT IDENTIFIER{id-PK-DH | id-PK-ECDH},
 *   chipAuthenticationPublicKey    SubjectPublicKeyInfo,
 *   keyID							INTEGER OPTIONAL
 * }
 * </pre>
 */
public class ChipAuthenticationPublicKeyInfo extends ASN1Encodable{
	
	private DERObjectIdentifier protocol = null;
	private SubjectPublicKeyInfo capk = null;
	private DERInteger keyId = null;
	
	public ChipAuthenticationPublicKeyInfo(DERSequence seq) {
		protocol = (DERObjectIdentifier) seq.getObjectAt(0);
		capk = new SubjectPublicKeyInfo((DERSequence)seq.getObjectAt(1));
		if (seq.size()==3) {
			keyId = (DERInteger)seq.getObjectAt(2);
		}	
	}
	
	public DERObjectIdentifier getProtocol() {
		return protocol;
	}
	
	public SubjectPublicKeyInfo getPublicKey() {
		return capk;
	}
	
	public int getKeyId() {
		return keyId.getPositiveValue().intValue();
	}
	
	@Override
	public String toString() {
		return "ChipAuthenticationPublicKeyInfo \n\tprotocol: "
				+ getProtocol() + "\n\tSubjectPublicKeyInfo: \n\t\t"
				+ "Algorithm: "+ getPublicKey().getAlgorithm().getAlgorithm() + "\n\t\t"
				+ "AmPublicKey:" + HexString.bufferToHex(getPublicKey().getPublicKey()) + "\n\tKeyID "
				+ getKeyId() + "\n";
	}
	
	
	/**
	 * The definition of ChipAuthenticationPublicKeyInfo is
     * <pre>
     * ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
     *      protocol					OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
     *      chipAuthenticationPublicKey	SubjectPublicKeyInfo,
     *      keyID						INTEGER OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(protocol);
		vec.add(capk);
		if (keyId!=null) {
			vec.add(keyId);
		}
		return new DERSequence(vec);
	}
	
	

}
