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
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertSignature extends ASN1Encodable{
	
	DERApplicationSpecific cvcsig = null;
	
	public CVCertSignature(byte[] signatureContent) {
		cvcsig = new DERApplicationSpecific(0x37, signatureContent);
	}
	
	public CVCertSignature(DERApplicationSpecific derApp) throws IllegalArgumentException {
		if (derApp.getApplicationTag()!=0x37) throw new IllegalArgumentException("Contains no Signature with tag 0x5F37");
	else cvcsig = derApp;
	}
	
	@Override
	public byte[] getDEREncoded() {
		return cvcsig.getDEREncoded();
	}
	
	public byte[] getSignature() {
		return cvcsig.getContents();
	}

	/* (non-Javadoc)
	 * @see org.spongycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public DERObject toASN1Object() {
		return cvcsig;
	}

}
