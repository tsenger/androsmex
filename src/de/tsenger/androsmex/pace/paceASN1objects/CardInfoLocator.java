/*
 * CardInfoLocator
 * OID: 0.4.0.127.0.7.2.2.6
 */

package de.tsenger.androsmex.pace.paceASN1objects;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1IA5String;
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
public class CardInfoLocator extends ASN1Sequence{

     /**
     * The object identifier for a CardInfoLocator object
     */
    private ASN1ObjectIdentifier protocol_ = null;

    /**
     * The String url SHALL define the location that provides the most recent
     * CardInfo file
     */
    private ASN1IA5String url_ = null;

    /**
     * The FileID efCardInfo MAY be used to indicate a (short) file identifier
     * for the file EF.CardInfo
     */
    private FileID efCardInfo_ = null;

    /**
    * Constructor for encoding. Setting a value for the optional field efCardInfo.
    *
    * @param protocolOID The OID of CardInfoLocator
    * @param url Defines the location that provides the most recent CardInfo file
    * @param efCardInfo May be used to indicate a (short) file identifier
    * for the file EF.CardInfo
    */
    public CardInfoLocator (String protocolOID, String url, FileID efCardInfo)
    {
        /* Allocate memory for the member variables.
         */
        super (3);

        /* Create ASN.1 objects with the parameters
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        url_ = new ASN1IA5String(url);
        efCardInfo_ = efCardInfo;

        /* Add the member variables to this class.
         */
        add(protocol_);
        add(url_);
        add(efCardInfo_);
    }

    /**
    * Constructor for encoding. Leaving the optional field efCardInfo empty.
    *
    * @param protocolOID The OID of CardInfoLocator
    * @param url Defines the location that provides the most recent CardInfo file
    */
    public CardInfoLocator (String protocolOID, String url)
    {
        /* Allocate memory for the member variable.
         */
        super (2);

        /* Create ASN.1 objects with the parameter
         */
        protocol_ = new ASN1ObjectIdentifier(protocolOID);
        url_ = new ASN1IA5String(url);

        /* Add the member variable to this class.
         */
        add(protocol_);
        add(url_);
    }

    /**
     * Constructor for decoding
     */
    public CardInfoLocator()
    {
        super(3);

        protocol_ = new ASN1ObjectIdentifier();
        url_ = new ASN1IA5String();
        efCardInfo_ = new FileID();
        efCardInfo_.setOptional(true);

        add(protocol_);
        add(url_);
        add(efCardInfo_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(protocol_);
        add(url_);
        if (efCardInfo_ != null)
        {
            add(efCardInfo_);
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
     * Set URL
     *
     * @param url String that contains url to CardInfo
     */
    public void setUrl(String url)
    {
        url_ = new ASN1IA5String(url);
    }

    /**
     * Get URL
     *
     * @return String that contains url to CardInfo
     */
    public String getUrl()
    {
        return url_.getString();
    }

     /**
     * Set efCardInfo
     *
     * @param efCardInfo Reference to FileID object containg the fid to EF.CardInfo
     */
    public void setEFCardInfo(FileID efCardInfo)
    {
        efCardInfo_ = efCardInfo;
    }

    /**
     * Get efCardInfo
     *
     * @return FileID containing the file identifier to EF.CardInfo
     */
    public FileID getEFCardInfo()
    {
        return efCardInfo_;
    }

    /**
     * Remove the value of the optional field
     */
    public void removeEFCardInfo()
    {
        efCardInfo_ = null;
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
