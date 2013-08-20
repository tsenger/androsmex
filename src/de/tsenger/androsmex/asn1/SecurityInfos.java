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
import java.util.ArrayList;
import java.util.List;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;

/**
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 */

public class SecurityInfos extends ASN1Encodable {

	List<TerminalAuthenticationInfo> terminalAuthenticationInfoList = new ArrayList<TerminalAuthenticationInfo>(3);
	List<ChipAuthenticationInfo> chipAuthenticationInfoList = new ArrayList<ChipAuthenticationInfo>(3);
	List<PaceInfo> paceInfoList = new ArrayList<PaceInfo>(3);
	List<PaceDomainParameterInfo> paceDomainParameterInfoList = new ArrayList<PaceDomainParameterInfo>(3);
	List<ChipAuthenticationDomainParameterInfo> chipAuthenticationDomainParameterInfoList = new ArrayList<ChipAuthenticationDomainParameterInfo>(3);
	List<CardInfoLocator> cardInfoLocatorList = new ArrayList<CardInfoLocator>(1);
	List<PrivilegedTerminalInfo> privilegedTerminalInfoList = new ArrayList<PrivilegedTerminalInfo>(1);
	List<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfoList = new ArrayList<ChipAuthenticationPublicKeyInfo>(3);

	private byte[] encodedData = null;

	public SecurityInfos() {
	}

	/**
	 * Decodes the byte array passed as argument. The decoded values are stored
	 * in the member variables of this class that represent the components of
	 * the corresponding ASN.1 type.
	 * 
	 * @param encodedData DOCUMENT ME!
	 * 
	 * @throws IOException DOCUMENT ME!
	 */
	public void decode(byte[] encodedData) throws IOException {
		this.encodedData = encodedData;
		ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
		int anzahlObjekte = securityInfos.size();
		DERSequence securityInfo[] = new DERSequence[anzahlObjekte];

		for (int i = 0; i < anzahlObjekte; i++) {
			securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
			DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i]
					.getObjectAt(0);

			switch (oid.toString().charAt(18)) {
			case '1': 
				chipAuthenticationPublicKeyInfoList.add(new ChipAuthenticationPublicKeyInfo(securityInfo[i]));
				break;
			case '2':
				terminalAuthenticationInfoList.add(new TerminalAuthenticationInfo(securityInfo[i]));
				break;
			case '3':
				if (oid.toString().length() == 23)
					chipAuthenticationInfoList.add(new ChipAuthenticationInfo(securityInfo[i]));
				else
					chipAuthenticationDomainParameterInfoList.add(new ChipAuthenticationDomainParameterInfo(securityInfo[i]));
				break;
			case '4':
				if (oid.toString().length() == 23)
					paceInfoList.add(new PaceInfo(securityInfo[i]));
				else
					paceDomainParameterInfoList.add(new PaceDomainParameterInfo(securityInfo[i]));
				break;
			case '6':
				cardInfoLocatorList.add(new CardInfoLocator(securityInfo[i]));
				break;
			case '8':
				privilegedTerminalInfoList.add(new PrivilegedTerminalInfo(securityInfo[i]));
				break;
			} // SWITCH

		} // IF

	}

	@Override
	public String toString() {
		String summary = null;
		summary = "------------------\nSecurityInfos object contains\n"
				+ terminalAuthenticationInfoList.size()
				+ " TerminalAuthenticationInfo objects \n"
				+ chipAuthenticationInfoList.size()
				+ " ChipAuthenticationInfo objects \n"
				+ chipAuthenticationDomainParameterInfoList.size()
				+ " ChipAuthenticationDomainParameterInfo objects \n"
				+ chipAuthenticationPublicKeyInfoList.size()
				+ " ChipAuthenticationPublicKeyInfo objects \n"
				+ paceInfoList.size() + " PaceInfo objects \n"
				+ paceDomainParameterInfoList.size()
				+ " PaceDomainParameterInfo objects \n"
				+ cardInfoLocatorList.size() + " CardInfoLocator objects \n"
				+ privilegedTerminalInfoList.size()
				+ " PrivilegedTerminalInfo objects\n------------------\n";

		for (TerminalAuthenticationInfo item : terminalAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationInfo item : chipAuthenticationInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationDomainParameterInfo item : chipAuthenticationDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (ChipAuthenticationPublicKeyInfo item : chipAuthenticationPublicKeyInfoList) {
			summary = summary + item.toString();
		}
		for (PaceInfo item : paceInfoList) {
			summary = summary + item.toString();
		}
		for (PaceDomainParameterInfo item : paceDomainParameterInfoList) {
			summary = summary + item.toString();
		}
		for (CardInfoLocator item : cardInfoLocatorList) {
			summary = summary + item.toString();
		}
		for (PrivilegedTerminalInfo item : privilegedTerminalInfoList) {
			summary = summary + item.toString();
		}

		return summary;
	}

	public byte[] getBytes() {
		return encodedData;
	}

	public List<PaceInfo> getPaceInfoList() {
		return paceInfoList;
	}

	public List<TerminalAuthenticationInfo> getTerminalAuthenticationInfoList() {
		return terminalAuthenticationInfoList;
	}

	public List<ChipAuthenticationInfo> getChipAuthenticationInfoList() {
		return chipAuthenticationInfoList;
	}

	public List<CardInfoLocator> getCardInfoLocatorList() {
		return cardInfoLocatorList;
	}

	public List<ChipAuthenticationDomainParameterInfo> getChipAuthenticationDomainParameterInfoList() {
		return chipAuthenticationDomainParameterInfoList;
	}

	public List<PaceDomainParameterInfo> getPaceDomainParameterInfoList() {
		return paceDomainParameterInfoList;
	}
	
	public List<ChipAuthenticationPublicKeyInfo> getChipAuthenticationPublicKeyInfoList() {
		return chipAuthenticationPublicKeyInfoList;
	}

	/**
	 * The definition of SecurityInfos is
     * <pre>
     * SecurityInfos ::= SET OF SecurityInfo
     * 
     * SecurityInfo ::= SEQUENCE {
     * 		protocol		OBJECT IDENTIFIER,
     * 		requiredData	ANY DEFINED BY protocol,
     * 		optionalData	ANY DEFINED BY protocol OPTIONAL
     * }
     * </pre>
	 */
	@Override
	public DERObject toASN1Object() {
		
		ASN1EncodableVector v = new ASN1EncodableVector();
		
		for (TerminalAuthenticationInfo item : terminalAuthenticationInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationInfo item : chipAuthenticationInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationDomainParameterInfo item : chipAuthenticationDomainParameterInfoList) {
			v.add(item);
		}
		for (ChipAuthenticationPublicKeyInfo item : chipAuthenticationPublicKeyInfoList) {
			v.add(item);
		}
		for (PaceInfo item : paceInfoList) {
			v.add(item);
		}
		for (PaceDomainParameterInfo item : paceDomainParameterInfoList) {
			v.add(item);
		}
		for (CardInfoLocator item : cardInfoLocatorList) {
			v.add(item);
		}
		for (PrivilegedTerminalInfo item : privilegedTerminalInfoList) {
			v.add(item);
		}
		
		return new DERSet(v);
	}

}
