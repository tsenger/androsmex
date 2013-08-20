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

import org.spongycastle.asn1.DERObjectIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface BSIObjectIdentifiers {

	public static final String bsi_de = "0.4.0.127.0.7";

	// PACE OIDs
	public static final String id_PACE = new String(bsi_de + ".2.2.4");

	public static final DERObjectIdentifier id_PACE_DH_GM = new DERObjectIdentifier(
			id_PACE + ".1");
	public static final DERObjectIdentifier id_PACE_DH_GM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_DH_GM + ".1");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".2");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".3");
	public static final DERObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_DH_GM + ".4");

	public static final DERObjectIdentifier id_PACE_ECDH_GM = new DERObjectIdentifier(
			id_PACE + ".2");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".1");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".2");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".3");
	public static final DERObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_ECDH_GM + ".4");

	public static final DERObjectIdentifier id_PACE_DH_IM = new DERObjectIdentifier(
			id_PACE + ".3");
	public static final DERObjectIdentifier id_PACE_DH_IM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_DH_IM + ".1");
	public static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_DH_IM + ".2");
	public static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_DH_IM + ".3");
	public static final DERObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_DH_IM + ".4");

	public static final DERObjectIdentifier id_PACE_ECDH_IM = new DERObjectIdentifier(
			id_PACE + ".4");
	public static final DERObjectIdentifier id_PACE_ECDH_IM_3DES_CBC_CBC = new DERObjectIdentifier(
			id_PACE_ECDH_IM + ".1");
	public static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_PACE_ECDH_IM + ".2");
	public static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_PACE_ECDH_IM + ".3");
	public static final DERObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_PACE_ECDH_IM + ".4");

	// Chip Authentication OIDs

	public static final String id_CA = new String(bsi_de + ".2.2.3");

	public static final DERObjectIdentifier id_CA_DH = new DERObjectIdentifier(
			id_CA + ".1");
	public static final DERObjectIdentifier id_CA_DH_3DES_CBC_CBC = new DERObjectIdentifier(
			id_CA_DH + ".1");
	public static final DERObjectIdentifier id_CA_DH_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_CA_DH + ".2");
	public static final DERObjectIdentifier id_CA_DH_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_CA_DH + ".3");
	public static final DERObjectIdentifier id_CA_DH_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_CA_DH + ".4");

	public static final DERObjectIdentifier id_CA_ECDH = new DERObjectIdentifier(
			id_CA + ".2");
	public static final DERObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new DERObjectIdentifier(
			id_CA_ECDH + ".1");
	public static final DERObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_128 = new DERObjectIdentifier(
			id_CA_ECDH + ".2");
	public static final DERObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_192 = new DERObjectIdentifier(
			id_CA_ECDH + ".3");
	public static final DERObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_256 = new DERObjectIdentifier(
			id_CA_ECDH + ".4");

	// Chip Authentication Public Key OIDs

	public static final String id_PK = new String(bsi_de + ".2.2.1");
	public static final DERObjectIdentifier id_PK_DH = new DERObjectIdentifier(
			id_PK + ".1");
	public static final DERObjectIdentifier id_PK_ECDH = new DERObjectIdentifier(
			id_PK + ".2");

	// Terminal Authentication OIDs
	public static final String id_TA = new String(bsi_de + ".2.2.2");

	public static final DERObjectIdentifier id_TA_RSA = new DERObjectIdentifier(
			id_TA + ".1");
	public static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_1 = new DERObjectIdentifier(
			id_TA_RSA + ".1");
	public static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_256 = new DERObjectIdentifier(
			id_TA_RSA + ".2");
	public static final DERObjectIdentifier id_TA_RSA_PSS_SHA_1 = new DERObjectIdentifier(
			id_TA_RSA + ".3");
	public static final DERObjectIdentifier id_TA_RSA_PSS_SHA_256 = new DERObjectIdentifier(
			id_TA_RSA + ".4");
	public static final DERObjectIdentifier id_TA_RSA_v1_5_SHA_512 = new DERObjectIdentifier(
			id_TA_RSA + ".5");
	public static final DERObjectIdentifier id_TA_RSA_PSS_SHA_512 = new DERObjectIdentifier(
			id_TA_RSA + ".6");

	public static final DERObjectIdentifier id_TA_ECDSA = new DERObjectIdentifier(
			id_TA + ".2");
	public static final DERObjectIdentifier id_TA_ECDSA_SHA_1 = new DERObjectIdentifier(
			id_TA_ECDSA + ".1");
	public static final DERObjectIdentifier id_TA_ECDSA_SHA_224 = new DERObjectIdentifier(
			id_TA_ECDSA + ".2");
	public static final DERObjectIdentifier id_TA_ECDSA_SHA_256 = new DERObjectIdentifier(
			id_TA_ECDSA + ".3");
	public static final DERObjectIdentifier id_TA_ECDSA_SHA_384 = new DERObjectIdentifier(
			id_TA_ECDSA + ".4");
	public static final DERObjectIdentifier id_TA_ECDSA_SHA_512 = new DERObjectIdentifier(
			id_TA_ECDSA + ".5");

	// Restricted Identification OIDs
	public static final String id_RI = new String(bsi_de + ".2.2.5");

	public static final DERObjectIdentifier id_RI_DH = new DERObjectIdentifier(
			id_RI + ".1");
	public static final DERObjectIdentifier id_RI_DH_SHA_1 = new DERObjectIdentifier(
			id_RI_DH + ".1");
	public static final DERObjectIdentifier id_RI_DH_SHA_224 = new DERObjectIdentifier(
			id_RI_DH + ".2");
	public static final DERObjectIdentifier id_RI_DH_SHA_256 = new DERObjectIdentifier(
			id_RI_DH + ".3");
	public static final DERObjectIdentifier id_RI_DH_SHA_384 = new DERObjectIdentifier(
			id_RI_DH + ".4");
	public static final DERObjectIdentifier id_RI_DH_SHA_512 = new DERObjectIdentifier(
			id_RI_DH + ".5");

	public static final DERObjectIdentifier id_RI_ECDH = new DERObjectIdentifier(
			id_RI + ".2");
	public static final DERObjectIdentifier id_RI_ECDH_SHA_1 = new DERObjectIdentifier(
			id_RI_ECDH + ".1");
	public static final DERObjectIdentifier id_RI_ECDH_SHA_224 = new DERObjectIdentifier(
			id_RI_ECDH + ".2");
	public static final DERObjectIdentifier id_RI_ECDH_SHA_256 = new DERObjectIdentifier(
			id_RI_ECDH + ".3");
	public static final DERObjectIdentifier id_RI_ECDH_SHA_384 = new DERObjectIdentifier(
			id_RI_ECDH + ".4");
	public static final DERObjectIdentifier id_RI_ECDH_SHA_512 = new DERObjectIdentifier(
			id_RI_ECDH + ".5");

	// CardInfoLocator OID
	public static final DERObjectIdentifier id_CI = new DERObjectIdentifier(
			bsi_de + ".2.2.6");

	// eIDSecurityInfo
	public static final DERObjectIdentifier id_eIDSecurity = new DERObjectIdentifier(
			bsi_de + ".2.2.7");

	// PrivilegedTerminalInfo
	public static final DERObjectIdentifier id_PT = new DERObjectIdentifier(
			bsi_de + ".2.2.8");

	// Roles
	public static final DERObjectIdentifier id_roles = new DERObjectIdentifier(
			bsi_de + ".3.1.2");

	public static final DERObjectIdentifier id_IS = new DERObjectIdentifier(
			id_roles + ".1");
	public static final DERObjectIdentifier id_AT = new DERObjectIdentifier(
			id_roles + ".2");
	public static final DERObjectIdentifier id_ST = new DERObjectIdentifier(
			id_roles + ".3");

	// Standardized Domain Parameters
	public static final DERObjectIdentifier standardizedDomainParameters = new DERObjectIdentifier(
			bsi_de + ".1.2");

	// Elliptic Curve OIDs (see BSI TR-03111 V1.11)
	public static final DERObjectIdentifier id_ecc = new DERObjectIdentifier(
			bsi_de + ".1.1");
	public static final DERObjectIdentifier ansi_X9_62 = new DERObjectIdentifier(
			"1.2.840.10045");

	public static final DERObjectIdentifier id_publicKeyType = new DERObjectIdentifier(
			ansi_X9_62 + ".2");
	public static final DERObjectIdentifier id_ecPublicKey = new DERObjectIdentifier(
			id_publicKeyType + ".1");

	public static final DERObjectIdentifier id_ecTLVKeyFormat = new DERObjectIdentifier(
			id_ecc + ".2.2");
	public static final DERObjectIdentifier id_ecTLVPublicKey = new DERObjectIdentifier(
			id_ecTLVKeyFormat + ".1");

	public static final DERObjectIdentifier ecdsa_plain_signatures = new DERObjectIdentifier(
			id_ecc + ".4.1");
	public static final DERObjectIdentifier ecdsa_plain_SHA1 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".1");
	public static final DERObjectIdentifier ecdsa_plain_SHA224 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".2");
	public static final DERObjectIdentifier ecdsa_plain_SHA256 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".3");
	public static final DERObjectIdentifier ecdsa_plain_SHA384 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".4");
	public static final DERObjectIdentifier ecdsa_plain_SHA512 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".5");
	public static final DERObjectIdentifier ecdsa_plain_RIPEMD160 = new DERObjectIdentifier(
			ecdsa_plain_signatures + ".6");

	public static final DERObjectIdentifier id_ecSigType = new DERObjectIdentifier(
			ansi_X9_62 + ".4");
	public static final DERObjectIdentifier ecdsa_with_Sha1 = new DERObjectIdentifier(
			id_ecSigType + ".1");
	public static final DERObjectIdentifier ecdsa_with_Specified = new DERObjectIdentifier(
			id_ecSigType + ".3");
	public static final DERObjectIdentifier ecdsa_with_Sha224 = new DERObjectIdentifier(
			ecdsa_with_Specified + ".1");
	public static final DERObjectIdentifier ecdsa_with_Sha256 = new DERObjectIdentifier(
			ecdsa_with_Specified + ".2");
	public static final DERObjectIdentifier ecdsa_with_Sha384 = new DERObjectIdentifier(
			ecdsa_with_Specified + ".3");
	public static final DERObjectIdentifier ecdsa_with_Sha512 = new DERObjectIdentifier(
			ecdsa_with_Specified + ".4");

	public static final DERObjectIdentifier ecka_eg = new DERObjectIdentifier(
			id_ecc + ".5.1");
	public static final DERObjectIdentifier ecka_eg_X963KDF = new DERObjectIdentifier(
			ecka_eg + ".1");
	public static final DERObjectIdentifier ecka_eg_X963KDF_SHA1 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".1");
	public static final DERObjectIdentifier ecka_eg_X963KDF_SHA224 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".2");
	public static final DERObjectIdentifier ecka_eg_X963KDF_SHA256 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".3");
	public static final DERObjectIdentifier ecka_eg_X963KDF_SHA384 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".4");
	public static final DERObjectIdentifier ecka_eg_X963KDF_SHA512 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".5");
	public static final DERObjectIdentifier ecka_eg_X963KDF_RIPEMD160 = new DERObjectIdentifier(
			ecka_eg_X963KDF + ".6");

	public static final DERObjectIdentifier ecka_eg_SessionKDF = new DERObjectIdentifier(
			ecka_eg + ".2");
	public static final DERObjectIdentifier ecka_eg_SessionKDF_3DES = new DERObjectIdentifier(
			ecka_eg_SessionKDF + ".1");
	public static final DERObjectIdentifier ecka_eg_SessionKDF_AES128 = new DERObjectIdentifier(
			ecka_eg_SessionKDF + ".2");
	public static final DERObjectIdentifier ecka_eg_SessionKDF_AES192 = new DERObjectIdentifier(
			ecka_eg_SessionKDF + ".3");
	public static final DERObjectIdentifier ecka_eg_SessionKDF_AES256 = new DERObjectIdentifier(
			ecka_eg_SessionKDF + ".4");

	public static final DERObjectIdentifier ecka_dh = new DERObjectIdentifier(
			id_ecc + ".5.2");
	public static final DERObjectIdentifier ecka_dh_X963KDF = new DERObjectIdentifier(
			ecka_dh + ".1");
	public static final DERObjectIdentifier ecka_dh_X963KDF_SHA1 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".1");
	public static final DERObjectIdentifier ecka_dh_X963KDF_SHA224 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".2");
	public static final DERObjectIdentifier ecka_dh_X963KDF_SHA256 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".3");
	public static final DERObjectIdentifier ecka_dh_X963KDF_SHA384 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".4");
	public static final DERObjectIdentifier ecka_dh_X963KDF_SHA512 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".5");
	public static final DERObjectIdentifier ecka_dh_X963KDF_RIPEMD160 = new DERObjectIdentifier(
			ecka_dh_X963KDF + ".6");

	public static final DERObjectIdentifier ecka_dh_SessionKDF = new DERObjectIdentifier(
			ecka_dh + ".2");
	public static final DERObjectIdentifier ecka_dh_SessionKDF_3DES = new DERObjectIdentifier(
			ecka_dh_SessionKDF + ".1");
	public static final DERObjectIdentifier ecka_dh_SessionKDF_AES128 = new DERObjectIdentifier(
			ecka_dh_SessionKDF + ".2");
	public static final DERObjectIdentifier ecka_dh_SessionKDF_AES192 = new DERObjectIdentifier(
			ecka_dh_SessionKDF + ".3");
	public static final DERObjectIdentifier ecka_dh_SessionKDF_AES256 = new DERObjectIdentifier(
			ecka_dh_SessionKDF + ".4");

}
