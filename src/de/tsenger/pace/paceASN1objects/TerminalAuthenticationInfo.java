/*
 * TerminalAuthenticationInfo
 * OID: 0.4.0.127.0.7.2.2.2
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
public class TerminalAuthenticationInfo extends ASN1Sequence{

    /**
    * The object identifier protocol SHALL identify the general Terminal Authentication Potocol
    * as the specific protocol may change over time.
    */
    private ASN1ObjectIdentifier protocol_ = null;

    /**
    * The integer version SHALL identify the version of the protocol. Currently,
    * versions 1 and 2 are supported.
    */
    private ASN1Integer version_ = null;

    /**
    * The sequence efCVCA MAY be used to indicate a (short) file identifier
    * of the file EF.CVCA. It MUST be used, if the default (short) file identifier is not used.
    * MUST NOT be used for version 2.
    */
    private FileID efCVCA_ = null;

    /**
    * Constructor for encoding. Setting a value for the optional field efCVCA.
    *
    * @param protocolOID The OID of the protocol
    * @param version Must be 1 or 2
    * @param efCVCA FileID object MUST NOT be used for version 2
    */
    public TerminalAuthenticationInfo (String protocolOID, Integer version, FileID efCVCA)
    {
        /* Allocate memory for the member variables.
         */
        super (3);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        version_ = new ASN1Integer(version);
        efCVCA_ = efCVCA;

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(version_);
        add(efCVCA_);
    }

    /**
    * Constructor for encoding. Leaving the optional field efCVCA empty.
    *
    * @param protocolOID The OID of the protocol
    * @param version Must be 1 or 2
    */
    public TerminalAuthenticationInfo (String protocolOID, Integer version)
    {
        /* Allocate memory for the member variable.
         */
        super (2);

        /* Create ASN.1 objects with the parameter
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        version_ = new ASN1Integer(version);

        /* Add the member variable to this class.
         */
        add(protocol_);
        add(version_);
    }

    /**
     * Constructor for decoding
     */
    public TerminalAuthenticationInfo()
    {
        super(3);

        protocol_ = new ASN1ObjectIdentifier();
        version_ = new ASN1Integer();
        efCVCA_ = new FileID();
        efCVCA_.setOptional(true);

        add(protocol_);
        add(version_);
        add(efCVCA_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(protocol_);
        add(version_);
        if (efCVCA_ != null)
        {
            add(efCVCA_);
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
     * @return byte array contains protocol OID
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
     * Set efCVCA
     *
     * @param Reference to FileID object containg the efCVCA
     */
    public void setEFCVCA(FileID efCVCA)
    {
        efCVCA_ = efCVCA;
    }

    /**
     * Get efCVCA
     *
     * @return byte array contains reference to FileID object
     */
    public FileID getEFCVCA()
    {
        return efCVCA_;
    }

    /**
     * Remove the value of the optional field
     */
    public void removeEFCVCA()
    {
        efCVCA_ = null;
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
