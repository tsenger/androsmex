/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package de.tsenger.pace.paceASN1objects;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.AbstractOIDRegistry;
import codec.asn1.OIDRegistry;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author senger
 */
public class EAC2OIDRegistry extends AbstractOIDRegistry{

    //Store each OID as an array of integers.
    static final private int[][] oids_ =
    {
        {0,4,0,127,0,7}, //bsi-de
        {0,4,0,127,0,7,2,2,4,1}, //id-PACE-DH-GM
        {0,4,0,127,0,7,2,2,4,1,1},

        {0,4,0,127,0,7,2,2,4,2}, //id-PACE-ECDH-GM
        {0,4,0,127,0,7,2,2,4,2,1},
        {0,4,0,127,0,7,2,2,4,2,2},
    };

    static final private Object[] types_ =
    {
        "bsi-de",
        "id-PACE-DH-GM",
        "id-PACE-DH-GM-3DES-CBC-CBC",

        "id-PACE-ECDH-GM",
        "id-PACE-ECDH-GM-3DES-CBC-CBC",
        "id-PACE-ECDH-GM-AES-CBC-CMAC-128"
    };

    static final private String prefix_ = "pacetest.oidRegistry.";

    static private Map map_ = new HashMap();

    /**
     * Contructor
     */
    public EAC2OIDRegistry(OIDRegistry parent)
    {
        super(parent);

        synchronized(map_)
        {
            if (map_.size() == 0)
            {
                for (int i=0; i<types_.length; i++)
                {
                    map_.put(new ASN1ObjectIdentifier(oids_[i]), types_[i]);
                }
            }
        }
    }


    @Override
    protected String getPrefix() {
        return prefix_;
    }

    @Override
    protected Map getOIDMap() {
        return map_;
    }

}
