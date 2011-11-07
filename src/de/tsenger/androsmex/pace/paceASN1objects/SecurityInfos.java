/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.androsmex.pace.paceASN1objects;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Set;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Tobias Senger (jsmex@t-senger.de)
 */
public class SecurityInfos extends ASN1Set{
    
    /**Contains the encoded Set
     * 
     */
    private ASN1Set securityInfosSet = null;

    /**
     * Contains TerminalAuthenticationInfo decoded from this set
     */
    private TerminalAuthenticationInfo terminalAuthenticationInfo_ = null;

    /**
     * Contains ChipAuthenticationInfo decoded from this set
     */
    private ChipAuthenticationInfo chipAuthenticationInfo_ = null;
    private ChipAuthenticationInfo chipAuthenticationInfo2_ = null;

    /**
     * Contains PACEInfo decoded from this set
     */
    private PACEInfo paceInfo_ = null;

    /**
     * Contains CardInfoLocator decoded from this set
     */
    private CardInfoLocator cardInfoLocator_ = null;

    /**
     * Contains ChipAuthenticationDomainParameterInfo decoded from this set
     */
    private ChipAuthenticationDomainParameterInfo caDomainParameterInfo_ = null;
    private ChipAuthenticationDomainParameterInfo caDomainParameterInfo2_ = null;

    /**
     * Contains PACEDomainParameterInfo decoded from this set
     */
    private PACEDomainParameterInfo paceDomainParameterInfo_ = null;
    

    public SecurityInfos()
    {
        super();

        terminalAuthenticationInfo_ = new TerminalAuthenticationInfo();
        chipAuthenticationInfo_ = new ChipAuthenticationInfo();
//        chipAuthenticationInfo2_ = new ChipAuthenticationInfo();
        paceInfo_ = new PACEInfo();
        caDomainParameterInfo_ = new ChipAuthenticationDomainParameterInfo();
//        caDomainParameterInfo2_ = new ChipAuthenticationDomainParameterInfo();
        cardInfoLocator_ = new CardInfoLocator();
        paceDomainParameterInfo_ = new PACEDomainParameterInfo();

        add(terminalAuthenticationInfo_);
        add(chipAuthenticationInfo_);
//        add(chipAuthenticationInfo2_);
        add(paceInfo_);
        add(cardInfoLocator_);
        add(caDomainParameterInfo_);
        add(paceDomainParameterInfo_);
        //add(caDomainParameterInfo2_);
        
//        
    }

    /* *
    * Constructor to create an object to be encoded. The data is provided by
    * the array given as a parameter .
    *
    * @param order Array DOCUMENT ME !
    */
    public SecurityInfos(ASN1Sequence[] sequenceArray)
    {
        super (sequenceArray.length);
        /* Add the elements of the array to this class .
        */
        for (int i=0; i<sequenceArray.length; i ++)
        {
            add(sequenceArray[i]);
        }
    }

    /* *
    * Returns a byte array representing an encoded instance of this class.
    *
    * @ return DOCUMENT ME!
    *
    * @ throws ASN1Exception DOCUMENT ME!
    * @ throws IOException DOCUMENT ME!
    */
    public byte[] getEncoded() throws ASN1Exception, IOException
    {
        ByteArrayOutputStream out;
        DEREncoder encoder;
        byte [] encodedAsn1Object;
        out                     = new ByteArrayOutputStream();
        encoder                 = new DEREncoder(out);
        this.encode (encoder);
        encodedAsn1Object = out.toByteArray();
        encoder.close();
        return encodedAsn1Object;
    }


    /* *
    * Decodes the byte array passed as argument. The decoded values are
    * stored in the member variables of this class that represent the
    * components of the corresponding ASN.1 type.
    *
    * @param encodedData DOCUMENT ME!
    *
    * @ throws ASN1Exception DOCUMENT ME!
    * @ throws IOException DOCUMENT ME!
    */
    public void decode (byte[] encodedData) throws ASN1Exception, IOException
    {
        ByteArrayInputStream in;
        DERDecoder decoder;
        in                      = new ByteArrayInputStream (encodedData);
        decoder                 = new DERDecoder(in);

        this.decode(decoder);
//        securityInfosSet = (ASN1Set) decoder.readType().getValue(); //get the ASN1Set SecurityInfos
        
        decoder.close();

//        System.out.println("SecurityInfos contains "+securityInfosSet.size()+" objects");
//
//        for (int i=0; i<securityInfosSet.size(); i++)
//        {
//            /**
//             *  The elements are always Sequences
//             */
//            ASN1Sequence securityInfo = (ASN1Sequence) securityInfosSet.get(i);
//
//            /**
//             * Get the ObjectIdentifier to identify the protocol
//             */
//            ASN1ObjectIdentifier protocol = (ASN1ObjectIdentifier) securityInfo.get(0);
//
//            if (protocol.toString().equals("0.4.0.127.0.7.2.2.2")) //TerminalAuthenticationInfo
//            {
//                System.out.println("Found TerminalAuthenticationInfo object.");
//                decodeTAI(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//            else if (protocol.toString().matches("0\\.4\\.0\\.127\\.0\\.7\\.2\\.2\\.3\\.\\d+\\.\\d+"))
//            {
//                System.out.println("Found ChipAuthenticationInfo object.");
//                decodeCAI(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//            else if (protocol.toString().matches("0\\.4\\.0\\.127\\.0\\.7\\.2\\.2\\.4\\.\\d+\\.\\d+"))
//            {
//                System.out.println("Found PACEInfo object.");
//                decodePACEInfo(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//            else if (protocol.toString().equals("0.4.0.127.0.7.2.2.6"))
//            {
//                System.out.println("Found CardInfoLocator object.");
//                decodeCIL(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//            else if (protocol.toString().matches("0\\.4\\.0\\.127\\.0\\.7\\.2\\.2\\.3\\.\\d+"))
//            {
//                System.out.println("Found ChipAuthenticationDomainParameterInfo object.");
//                decodeCADPI(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//            else if (protocol.toString().matches("0\\.4\\.0\\.127\\.0\\.7\\.2\\.2\\.4\\.\\d+"))
//            {
//                System.out.println("Found PACEDomainParameterInfo object.");
//                decodePACEDPI(getEncoded((ASN1Sequence)securityInfosSet.get(i)));
//            }
//        }


    }

    public TerminalAuthenticationInfo getTAI()
    {
        return terminalAuthenticationInfo_;
    }

    public ChipAuthenticationInfo getCAI()
    {
        return chipAuthenticationInfo_;
    }

    public PACEInfo getPACEInfo()
    {
        return paceInfo_;
    }

    public CardInfoLocator getCIL()
    {
        return cardInfoLocator_;
    }

    public ChipAuthenticationDomainParameterInfo getCADPI()
    {
        return caDomainParameterInfo_;
    }

    public PACEDomainParameterInfo getPACEDPI()
    {
        return paceDomainParameterInfo_;
    }

    
}
