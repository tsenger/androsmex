/*
 * ChipAuthenticationDomainParameterInfo
 * OID: 0.4.0.127.0.7.2.2.3.x
 *
 * This data structure provides one set of domain parameters for
 * Chip Authentication of the MRTD chip.
 */

package de.tsenger.androsmex.pace.paceASN1objects;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Encoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author senger
 */
public class ChipAuthenticationDomainParameterInfo extends ASN1Sequence{

    /**
     * The object identifier protocol identifies the type of the domain parameter.
     * e.g. DH or ECDH
     */
    private ASN1ObjectIdentifier protocol_ = null;

    /**
     * The sequence domainParamter contains the domain paramters
     */
    private AlgorithmIdentifier domainParameter_ = null;

    /**
     * The integer keyID may be used to indicate the local key identifier.
     * It MUST be used if the MRTD chip provides multiple public keys
     * for Chip Authentication.
     */
    private ASN1Integer keyId_ = null;

    /**
    * Constructor for encoding. Setting a value for the optional field keyId.
    *
    * @param protocolOID The OID of the used domain parameters
    * @param dp Contains AlgorithmIdentifier object for the domain paramters.
    * @param keyId May be used to indicate the local key identifier.
    */
    public ChipAuthenticationDomainParameterInfo (String protocolOID, AlgorithmIdentifier dp, Integer keyId)
    {
        /* Allocate memory for the member variables.
         */
        super(3);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        domainParameter_ = dp;
        keyId_ = new ASN1Integer(keyId);

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(domainParameter_);
        add(keyId_);

    }

    /**
    * Constructor for encoding. Leaving the for the optional field keyId empty.
    *
    * @param protocolOID The OID of the used domain parameters
    * @param dp Contains AlgorithmIdentifier object for the domain paramters.
    */
    public ChipAuthenticationDomainParameterInfo (String protocolOID, AlgorithmIdentifier dp)
    {
        /* Allocate memory for the member variables.
         */
        super(2);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        domainParameter_ = dp;

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(domainParameter_);

    }

    /**
     * Constructor for decoding
     */
    public ChipAuthenticationDomainParameterInfo()
    {
        super(3);

        protocol_ = new ASN1ObjectIdentifier();
        domainParameter_ = new AlgorithmIdentifier();
        keyId_ = new ASN1Integer();
        keyId_.setOptional(true);

        add(protocol_);
        add(domainParameter_);
        add(keyId_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(protocol_);
        add(domainParameter_);
        if (keyId_ != null)
        {
            add(keyId_);
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
     * Set and get methods
     */

    /**
     * Set protocol OID
     *
     * @param protocolOID The OID identifies the used domain paramters.
     */
    public void setProtocol(String protocolOID)
    {
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
    }

    /**
     * Get protocol OID
     *
     * @return String contains OID of the used domain paramters
     */
    public String getProtocol()
    {
        return protocol_.toString();
    }

    /**
     * Set Domain Paramters
     *
     * @param dp AlgorithmIdentifier object contains the domain paramters.
     */
    public void setDomainParameter(AlgorithmIdentifier dp)
    {
        domainParameter_ = dp;
    }

    /**
     * Get Domain Parameters
     *
     * @return AlgorithmIdentifier object contains the domain paramters
     */
    public AlgorithmIdentifier getDomainParameter()
    {
        return (AlgorithmIdentifier) domainParameter_.clone();
    }

     /**
     * Set keyId
     *
     * @param keyId To indicate the local key identifier.
     */
    public void setKeyId(Integer keyId)
    {
        keyId_ = new ASN1Integer(keyId);
    }

    /**
     * Get keyId
     *
     * @return Integer contains keyID of the local key identifier
     */
    public Integer getKeyId()
    {
        return keyId_.getBigInteger().intValue();
    }

    /**
     * Remove the value of the optional field
     */
    public void removeKeyId()
    {
        keyId_ = null;
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
