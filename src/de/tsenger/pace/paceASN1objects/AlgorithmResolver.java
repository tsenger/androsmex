/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.pace.paceASN1objects;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import codec.asn1.Resolver;
import codec.asn1.ResolverException;
import de.flexiprovider.ec.asn1.ECDomainParameters;

/**
 *
 * @author senger
 */
class AlgorithmResolver implements Resolver{

    private ASN1ObjectIdentifier oid_;

    public AlgorithmResolver(ASN1ObjectIdentifier algorithmOID)
    {
        oid_ = algorithmOID;
    }

    /**
     * This method returns an empty instance of the appropriate ASN1 type
     * for decoding the ANY DEFINED BY value. When this method is called the
     * OBJECT IDENTIFIER pointed by oid_ has been decoded in the meantime, so
     * that its value can be queried.
     *
     * @param caller The instance from which this method will be called
     *
     * @return Returns an empty instance of the appropriate ASN1 type
     *
     * @throws ResolverException
     */
    public ASN1Type resolve(ASN1Type caller) throws ResolverException
    {
        if (oid_.toString().equals("1.2.840.10046.0.1")) //gfPrime
        {
            return new GfPrime();
        }
//        else if (oid_.toString().equals("1.2.840.10046.2.1")) //dhpublicnumber
//        {
//            return ;
//        }
        else if (oid_.toString().equals("1.2.840.10045.2.1")) //ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            return new ECDomainParameters();
        }
        else if (oid_.toString().equals("0.4.0.127.0.7.1.1.5.1.2")) //ecka-eg-SessionKDF->ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            return new ECDomainParameters();
        }
        else if (oid_.toString().equals("0.4.0.127.0.7.1.1.5.2.2.2")) //ecka-dh-SessionKDF-AES128->ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            return new ECDomainParameters();
        }
        else if (oid_.toString().equals("0.4.0.127.0.7.1.2")) //standardizedDomainParameters
        {
            return new ASN1Integer();
        }
        else
        {
            throw new ResolverException();
        }
    }

}
