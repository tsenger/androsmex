
package de.tsenger.pace.paceASN1objects;



import java.io.IOException;

import ext.org.bouncycastle.asn1.ASN1Object;
import ext.org.bouncycastle.asn1.ASN1Sequence;
import ext.org.bouncycastle.asn1.ASN1Set;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import ext.org.bouncycastle.asn1.DERSequence;

/**
 *
 * @author Tobias Senger (jsmex@t-senger.de)
 */
public class SecurityInfos_bc {
    
    private DERSequence terminalAuthenticationInfo = null;
    private DERSequence chipAuthenticationInfo = null;
    private DERSequence paceInfo = null;
    private DERSequence paceDomainParameterInfo = null;
    private DERSequence chipAuthenticationDomainParameterInfo = null;
    private DERSequence cardInfoLocator = null;

    public SecurityInfos_bc()
    {
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
    public void decode (byte[] encodedData) throws IOException 
    {
    	
    	ASN1Set securityInfos = (ASN1Set) ASN1Object.fromByteArray(encodedData);
    	int anzahlObjekte = securityInfos.size();
    	DERSequence securityInfo[] = new DERSequence[anzahlObjekte];
    	    	
    	for (int i=0;i<anzahlObjekte;i++) {
    		securityInfo[i] = (DERSequence) securityInfos.getObjectAt(i);
    		DERObjectIdentifier oid = (DERObjectIdentifier) securityInfo[i].getObjectAt(0);
    		switch (oid.toString().charAt(18)) {
    		case '2': 
    			terminalAuthenticationInfo = securityInfo[i]; 
    			break;
    		case '3':
    			if (oid.toString().length()==23) chipAuthenticationInfo = securityInfo[i];
    			else chipAuthenticationDomainParameterInfo = securityInfo[i];
    			break;
    		case '4':
    			if (oid.toString().length()==23) paceInfo = securityInfo[i];
    			else paceDomainParameterInfo = securityInfo[i];
    			break;
    		case '6':
    			cardInfoLocator = securityInfo[i];
    			break;    	
    		} //SWITCH
    			
    	} // IF
    	

    }

    public DERSequence getTAI()
    {
        return terminalAuthenticationInfo;
    }

    public DERSequence getCAI()
    {
        return chipAuthenticationInfo;
    }

    public PaceInfo_bc getPACEInfo()
    {
        return new PaceInfo_bc(paceInfo);
    }

    public DERSequence getCIL()
    {
        return cardInfoLocator;
    }

    public DERSequence getCADPI()
    {
        return chipAuthenticationDomainParameterInfo;
    }

    public DERSequence getPACEDPI()
    {
        return paceDomainParameterInfo;
    }

    
}
