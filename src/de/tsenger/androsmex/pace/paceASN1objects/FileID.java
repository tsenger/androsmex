/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.androsmex.pace.paceASN1objects;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1OctetString;
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
public class FileID extends ASN1Sequence {

    /**
    * The octet string fid contains a file identifier
    */
    private ASN1OctetString fid_ = null;

    /**
    * The optional octet string sfid contains a short file identifier
    */
    private ASN1OctetString sfid_ = null;

    /**
    * Constructor for encoding, setting a value for the optional field sfid.
    *
    * @param protocolOID The OID of the protocol
    * @param requiredData Required data for the choosen protocol
    */
    public FileID (byte[] fid, byte[] sfid)
    {
        /* Allocate memory for the member variables.
         */
        super (2);

        /* Create ASN.1 objects with the parameters
         */
        fid_ = new ASN1OctetString(fid);
        sfid_ = new ASN1OctetString(sfid);

        /* Add the member variables to this class.
         */
        add(fid_);
        add(sfid_);
    }

    /* *
    * Constructor for encoding, leaving the optional field sfid empty.
    *
    * @param protocolOID The OID of the protocol
    * @param requiredData Required data for the choosen protocol
    */
    public FileID (byte[] fid)
    {
        /* Allocate memory for the member variable.
         */
        super (1);

        /* Create ASN.1 objects with the parameter
         */
        fid_ = new ASN1OctetString(fid);

        /* Add the member variable to this class.
         */
        add(fid_);
    }

    /* *
     * Constructor for decoding
     */
    public FileID()
    {
        super(2);

        fid_ = new ASN1OctetString();
        sfid_ = new ASN1OctetString();
        sfid_.setOptional(true);

        add(fid_);
        add(sfid_);
    }

    /**
     * Add only the components that will be encoded to class.
     */
    protected void map()
    {
        clear();

        add(fid_);
        if (sfid_ != null)
        {
            add(sfid_);
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
     * @param encodedData byte array to decode to the member variables fid and sfid
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

        this.decode(decoder); //this refer to the ASN1Sequence decode method
        decoder.close();
    }

    /**
     * Set and get methods
     */

    /**
     * Set file identifier fid
     *
     * @param fid file identifier
     */
    public void setFID(byte[] fid)
    {
        fid_ = new ASN1OctetString(fid);
    }

    /**
     * Get file identifier fid
     *
     * @return byte array contains file identifier fid
     */
    public byte[] getFID()
    {
        return fid_.getByteArray();
    }

    /**
     * Set short file identifier sfid
     *
     * @param sfid short file identifier
     */
    public void setSFID(byte[] sfid)
    {
        sfid_ = new ASN1OctetString(sfid);
        sfid_.setOptional(false);
    }

    /**
     * Get short file identifier sfid
     *
     * @return byte array contains short file identifier sfid
     */
    public byte[] getSFID()
    {
        return sfid_.getByteArray();
    }

    /**
     * Remove the value of the optional field
     */
    public void removeSFID()
    {
        sfid_ = null;
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
