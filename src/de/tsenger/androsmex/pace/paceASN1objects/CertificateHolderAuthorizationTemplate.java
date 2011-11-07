package de.tsenger.androsmex.pace.paceASN1objects;

import java.io.IOException;
import java.util.Arrays;
import ext.org.bouncycastle.asn1.DERObjectIdentifier;
import de.tsenger.androsmex.pace.PACEOID;

public class CertificateHolderAuthorizationTemplate {
	/**
	 * Der Tag für das Certificate Holder Authorization Template (CHAT) (0x7F4C)
	 */
	private static byte[] tag_ = {(byte)0x7F, (byte)0x4C};
	
	 /**
     * Der object identifier des Terminaltyps (IS, AT, ST)
     */
    private DERObjectIdentifier id_role = null;
    private byte[] id_roleBytes = null;
    
    private byte[] authorizationAT = null;
    private byte authorization = (byte)0xFF;
    private byte[] encodedChat = null;
    
    public CertificateHolderAuthorizationTemplate(DERObjectIdentifier oid) {
    	id_role = (DERObjectIdentifier) oid.getDERObject();
    	setTerminalOID(oid);
    }
    
    public void setTerminalOID(DERObjectIdentifier oid) {
    	id_role = (DERObjectIdentifier) oid.getDERObject();
    	try {
			id_roleBytes = id_role.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void setAuthorization(byte auth) {
    	authorization = auth;
    }
    
    public void setAuthorization(byte[] auth) {
    	try {
			if (Arrays.equals(id_role.getEncoded(), PACEOID.id_AT.getEncoded())&&auth.length==5) {
				authorizationAT = new byte[5];
				System.arraycopy(auth, 0, authorizationAT, 0, 5);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public byte[] getEncodedChat() {
    	if (authorizationAT!=null) {
    		encodedChat = new byte[tag_.length+1+id_roleBytes.length+7];
    		encodedChat[0] = tag_[0];
    		encodedChat[1] = tag_[1];
    		encodedChat[2] = (byte)(id_roleBytes.length+7);
    		System.arraycopy(id_roleBytes, 0, encodedChat, 3, id_roleBytes.length);
    		encodedChat[3+id_roleBytes.length] = (byte)0x53;
    		encodedChat[4+id_roleBytes.length] = (byte)0x05;
    		System.arraycopy(authorizationAT, 0, encodedChat, (5+id_roleBytes.length), authorizationAT.length);
    		
    	}
    	else {
    		encodedChat = new byte[tag_.length+1+id_roleBytes.length+3];
    		encodedChat[0] = tag_[0];
    		encodedChat[1] = tag_[1];
    		encodedChat[2] = (byte)(id_roleBytes.length+3);
    		System.arraycopy(id_roleBytes, 0, encodedChat, 3, id_roleBytes.length);
    		encodedChat[3+id_roleBytes.length] = (byte)0x53;
    		encodedChat[4+id_roleBytes.length] = (byte)0x01;
    		encodedChat[5+id_roleBytes.length] = authorization;
    	}
    	return encodedChat;
    }

}
