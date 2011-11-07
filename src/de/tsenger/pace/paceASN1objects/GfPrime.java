/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.pace.paceASN1objects;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import java.math.BigInteger;

/**
 *
 * @author senger
 */
class GfPrime extends ASN1Sequence {

    /**
     * Prime
     */
    private ASN1Integer p_ = null;

    /**
     * Generator
     */
    private ASN1Integer g_ = null;

    /**
     * Size of the prime order subgroup
     */
    private ASN1Integer q_ = null;

    /**
    * Constructor for encoding.
    *
    * @param p Prime
    * @param g Generator
    * @param q Size of the prime order subgroup
    */
    public GfPrime (BigInteger p, BigInteger g, BigInteger q)
    {
        /* Allocate memory for the member variables.
         */
        super (3);

        /* Create ASN.1 objects with the parameters
         */
        p_ = new ASN1Integer(p);
        g_ = new ASN1Integer(g);
        q_ = new ASN1Integer(q);

        /* Add the member variables to this class.
         */
        add(p_);
        add(g_);
        add(q_);
    }

    public GfPrime() 
    {
        super (3);

        p_ = new ASN1Integer();
        g_ = new ASN1Integer();
        q_ = new ASN1Integer();

        add(p_);
        add(g_);
        add(q_);
    }

}
