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
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;

/**
 * As described in BSI TR-03110 chpater D.2. Data Objects
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class DiscretionaryData extends ASN1Encodable{

	private DEROctetString data = null;
	
	/** Constructor for Encoding
	 * @param data
	 */
	public DiscretionaryData(byte[] data) {
		this.data = new DEROctetString(data);
	}

	/** Constructor for Encoding
	 * @param data
	 */
	public DiscretionaryData(byte data) {
		this.data = new DEROctetString(new byte[]{data});
	}


	/* (non-Javadoc)
	 * @see org.spongycastle.asn1.ASN1Encodable#toASN1Object()
	 */
	@Override
	public DERObject toASN1Object() {
		try {
			return new DERApplicationSpecific(false, 0x13, data);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] getData() {
		return data.getOctets();
	}
	

}
