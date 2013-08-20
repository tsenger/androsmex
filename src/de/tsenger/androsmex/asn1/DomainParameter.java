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

import static de.tsenger.androsmex.crypto.DHStandardizedDomainParameters.modp1024_160;
import static de.tsenger.androsmex.crypto.DHStandardizedDomainParameters.modp2048_224;
import static de.tsenger.androsmex.crypto.DHStandardizedDomainParameters.modp2048_256;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DomainParameter {
	
	private DHParameters dhParameters = null;
	private ECParameterSpec ecSpec = null;
	
	/**
	 * Extrahiert aus dem AlogorithmIdentifier standardisierte Parameter für DH oder ECDH.
	 * @param Referenz auf Standardized Domain Parameters
	 */
	public DomainParameter(int ref) {
		if (ref<0||ref>18) throw new UnsupportedOperationException("unsupported standardized Domain Parameters");
		else getParameters(ref);	
	}
	
	/**
	 * Extrahiert aus dem AlogorithmIdentifier die Parameter für DH oder ECDH.
	 * Es werden standardisierte DomainParameter und explizite DP erkannt.
	 * @param algorithm OID
	 */
	public DomainParameter(AlgorithmIdentifier aid) {
		if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.standardizedDomainParameters.toString())) {
			int dpref = ((DERInteger)aid.getParameters()).getPositiveValue().intValue(); 
			getParameters(dpref);	
		} 
		
		else if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.id_ecPublicKey)) {
			X9ECParameters x9ecp = new X9ECParameters((ASN1Sequence) aid.getParameters());
			ecSpec = new ECParameterSpec(x9ecp.getCurve(), x9ecp.getG(), x9ecp.getN());
		} //TODO properitäre DH Domain Parameter 
		
		else throw new UnsupportedOperationException("unsupported Domain Parameters");
	}

	/**
	 * @param dpref
	 */
	private void getParameters(int dpref) {
		switch (dpref) {
		case 0:
			dhParameters = modp1024_160();
			break;
		case 1:
			dhParameters = modp2048_224();
			break;
		case 3:
			dhParameters = modp2048_256();
			break;
		case 8:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
			break;
		case 9:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
			break;
		case 10:;
			ecSpec = ECNamedCurveTable.getParameterSpec("secp224r1");
			break;
		case 11:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp224r1");
			break;
		case 12:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			break;
		case 13:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
			break;
		case 14:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp320r1");
			break;
		case 15:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
			break;
		case 16:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp384r1");
			break;
		case 17:
			ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp512r1");
			break;
		case 18:
			ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
			break;
		}
	}
	
	public String getDPType() {
		if (ecSpec!=null) return "ECDH";
		else if (dhParameters!=null) return "DH";
		return null;
	}
	
	public ECParameterSpec getECParameter() {
		return ecSpec;
	}
	
	public DHParameters getDHParameter() {
		return dhParameters;
	}

}
