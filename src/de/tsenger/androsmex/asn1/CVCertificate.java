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
import org.spongycastle.asn1.ASN1StreamParser;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTags;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CVCertificate extends ASN1Encodable{
		
	private CVCertBody certBody = null;
	private CVCertSignature certSignature = null;
	
	public CVCertificate(byte[] in) throws IllegalArgumentException, IOException {
		ASN1StreamParser asn1Parser = new ASN1StreamParser(in);
		
		DERApplicationSpecific cvcert = (DERApplicationSpecific) asn1Parser.readObject();
		if (cvcert.getApplicationTag()!=0x21) throw new IllegalArgumentException("Can't find a CV Certificate");
		
		DERSequence derCert= (DERSequence)cvcert.getObject(DERTags.SEQUENCE); // Das CV Cerificate ist eine Sequence
		
		DERApplicationSpecific body = (DERApplicationSpecific) derCert.getObjectAt(0); //Das erste Objekt des Certificates ist der Cert-Body
		if (body.getApplicationTag()!=0x4E) throw new IllegalArgumentException("Can't find a Body in the CV Certificate");
		
		certBody = new CVCertBody(body);
		
		DERApplicationSpecific signature = (DERApplicationSpecific) derCert.getObjectAt(1); //Das zweite Objekt des Certificates ist die Signatur
		if (signature.getApplicationTag()!=0x37) throw new IllegalArgumentException("Can't find a Signature in the CV Certificate");

		certSignature = new CVCertSignature(signature.getContents());
		
	}
	
	public CVCertSignature getSignature() {
		return certSignature;
	}
	
	public CVCertBody getBody() {
		return certBody;
	}

	/** 
	 * The definition of CVCertificate is
     * <pre>
     * CVCertificate ::=  SEQUENCE {
     *      body     	CVCertBody
     *      signature	CVCertSignature
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(certBody);
        v.add(certSignature);
        
        return new DERApplicationSpecific(0x21, v);
	}

}
