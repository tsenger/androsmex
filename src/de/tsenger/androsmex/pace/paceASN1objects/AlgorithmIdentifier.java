/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.androsmex.pace.paceASN1objects;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Encoder;
import de.flexiprovider.ec.asn1.ECDomainParameters;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author senger
 */
public class AlgorithmIdentifier extends ASN1Sequence{

    /**
     * contains the OID of the used algorithm
     */
    private ASN1ObjectIdentifier algorithm_ = null;

    /**
     *  contains parameters defined by the algoritm (opional)
     */
    private ASN1Type parameter_ = null;

    /**
    * Constructor for encoding, with optional parameter object.
    *
    * @param algorithmOID The OID of the used algorithm
    * @param dp Contains AlgorithmIdentifier object for the domain paramters.
    */
    public AlgorithmIdentifier(String algorithmOID, Object parameterObj)
    {
        /* Allocate memory for the member variables.
         */
        super(2);

        /* Create ASN.1 objects with the parameters
         */
        algorithm_ = new ASN1ObjectIdentifier(algorithmOID);

        if (algorithmOID.equals("1.2.840.10046.0.1")) //gfPrime
        {
            parameter_ = (ASN1Type) parameterObj;
        }
        else if (algorithmOID.equals("1.2.840.10046.2.1")) //dhpublicnumber
        {
            parameter_ = (ASN1Type) parameterObj;
        }
        else if (algorithmOID.equals("1.2.840.10045.2.1")) //ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            parameter_ = (ECDomainParameters) parameterObj;
        }
        else if (algorithmOID.equals("0.4.0.127.0.7.1.1.5.1.2")) //ecka-eg-SessionKDF->ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            parameter_ = (ECDomainParameters) parameterObj;
        }
        else if (algorithmOID.equals("0.4.0.127.0.7.1.1.5.2.2.2")) //ecka-dh-SessionKDF-AES128->ecPublicKey
        {
            //ECDomainParameters is an ASN1Structure object of ECParameters in Flexiprovider
            parameter_ = (ECDomainParameters) parameterObj;
        }
        else if (algorithmOID.equals("0.4.0.127.0.7.1.2")) //standardizedDomainParameters
        {
            parameter_ = new ASN1Integer((Integer)parameterObj);
        }

        /* Add the member variables to this class.
         */
        add(algorithm_);
        add(parameter_);
    }

    /**
    * Constructor for encoding, without optional parameter object.
    *
    * @param algorithmOID The OID of the used algorithm
    */
    public AlgorithmIdentifier(String algorithmOID)
    {
        /* Allocate memory for the member variables.
         */
        super(1);

        /* Create ASN.1 objects with the parameters
         */
        algorithm_ = new ASN1ObjectIdentifier(algorithmOID);

        /* Add the member variables to this class.
         */
        add(algorithm_);
    }

    /**
     * Constructor for decoding
     */
    public AlgorithmIdentifier()
    {
        super(2);

        algorithm_ = new ASN1ObjectIdentifier();
        parameter_ = new ASN1OpenType(new AlgorithmResolver(algorithm_));
        parameter_.setOptional(true);

        add(algorithm_);
        add(parameter_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(algorithm_);
        if (parameter_ != null)
        {
            add(parameter_);
        }
    }

    /**
     * Override the encode(Encoder) method so that map() is called before
     * each call of this method.
     *
     * @param enc The Encoder Object
     *
     * @throws ASN1Exception
     * @throws IOException
     */
    @Override
    public void encode(Encoder enc) throws ASN1Exception, IOException
    {
       map();
       super.encode(enc);
    }

    /**
     * Returns a byte array representing an encoded instance of this class
     *
     * @return byte array containing encoded instance of this class
     *
     * @throws ASN1Exception
     * @throws IOException
     */
    public byte[] getEncoded() throws ASN1Exception, IOException
    {
        ByteArrayOutputStream out;
        DEREncoder encoder;
        byte[] encodedAsn1Object;

        out = new ByteArrayOutputStream();
        encoder = new DEREncoder(out);

        this.encode(encoder);
        encodedAsn1Object = out.toByteArray();
        encoder.close();

        return encodedAsn1Object;
    }

    /**
     * Decodes the given byte array. The decoded values are stored in the
     * member variables of this class that represent the components of the
     * ASN.1 type FileID.
     *
     * @param encodedData byte array to decode the member variables
     *
     * @throws ASN1Exception
     * @throws IOException
     */
    public void decode(byte[] encodedData) throws ASN1Exception, IOException
    {
        ByteArrayInputStream in;
        DERDecoder decoder;

        in = new ByteArrayInputStream(encodedData);
        decoder = new DERDecoder(in);

        this.decode(decoder); //this refers to the ASN1Sequence decode method
        decoder.close();
    }

    /**
     * Get methods
     */

    public ASN1ObjectIdentifier getAlgorithmOID()
    {
        return (ASN1ObjectIdentifier) algorithm_.clone();
    }

    public ASN1Type getParameter()
    {
        return parameter_;
    }

    /**
     * Override the toString() method so that map() is called before each
     * call of this method.
     *
     * @return
     */
    @Override
    public String toString()
    {
        map();
        return super.toString();
    }

}
