/*
 * PACEInfo
 * OID: 0.4.0.127.0.7.2.2.4.x.y
 *
 * This data structure provides detailed information on an implementaion
 * of PACE.
 */

package de.tsenger.pace.paceASN1objects;

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
public class PACEInfo extends ASN1Sequence{

    /**
     * The oject identifier protocol SHALL identify the algorithm to be used
     * (i.e. key agreement, symmetric cipher and MAC)
     */
    private ASN1ObjectIdentifier protocol_ = null;

   /**
    * The integer version SHALL identify the version of the protocol. Currently,
    * versions 1 and 2 are supported: Version 1 is restricted to the general
    * mapping. If the integrated mapping is used version 2 MUST be used.
    */
    private ASN1Integer version_ = null;

    /**
     * The integer parameterId is used to indicate the domain parameter identifier.
     * It MUST be used if the MRTD chip uses standardized domain parameters or
     * provides multiple proprietary domain parameters for PACE
     */
    private ASN1Integer parameterId_ = null;

    /**
    * Constructor for encoding. Setting a value for the optional field keyId.
    *
    * @param protocolOID The OID of the protocol
    * @param version Must be 1 or 2
    * @param parameterId Indicates the domain parameter identifier.
    */
    public PACEInfo (String protocolOID, Integer version, Integer parameterId)
    {
        /* Allocate memory for the member variables.
         */
        super (3);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        version_ = new ASN1Integer(version);
        parameterId_ = new ASN1Integer(parameterId);

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(version_);
        add(parameterId_);
    }

    /**
    * Constructor for encoding. Leaving the optional field keyId empty.
    *
    * @param protocolOID The OID of the protocol
    * @param version Must be 1 or 2
    * @param keyId Indicates the local key identifier
    */
    public PACEInfo (String protocolOID, Integer version)
    {
        /* Allocate memory for the member variables.
         */
        super (2);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        version_ = new ASN1Integer(version);

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(version_);
    }

    /**
     * Constructor for decoding
     */
    public PACEInfo()
    {
        super(3);

        protocol_ = new ASN1ObjectIdentifier();
        version_ = new ASN1Integer();
        parameterId_ = new ASN1Integer();
        parameterId_.setOptional(true);

        add(protocol_);
        add(version_);
        add(parameterId_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(protocol_);
        add(version_);
        if (parameterId_ != null)
        {
            add(parameterId_);
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
     * @param protocolOID OID of the used protocol
     */
    public void setProtocol(String protocolOID)
    {
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
    }

    /**
     * Get protocol OID
     *
     * @return String contains protocol OID
     */
    public ASN1ObjectIdentifier getProtocol()
    {
        return (ASN1ObjectIdentifier) protocol_.clone();
    }

    /**
     * Set version (1 or 2)
     *
     * @param version The version to be used (1 or 2)
     */
    public void setVersion(Integer version)
    {
        version_ = new ASN1Integer(version);
    }

    /**
     * Get version
     *
     * @return byte array contains version of used protocol
     */
    public Integer getVersion()
    {
        return version_.getBigInteger().intValue();
    }

     /**
     * Set keyId
     *
     * @param parameterId Indicates the domain parameter identifier
     */
    public void setParameterId(Integer keyId)
    {
        parameterId_ = new ASN1Integer(keyId);
    }

    /**
     * Get keyId
     *
     * @return Integer contains parameterId
     */
    public Integer getParameterId()
    {
        return parameterId_.getBigInteger().intValue();
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
