package de.tsenger.androsmex.iso7816;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;



public class DO97{

    private byte[] data = null;;
    private DERTaggedObject to = null;
	
	public DO97(){}
	
	public DO97(byte[] le) {
		data = le.clone();
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));
	}
	
	public DO97(int le) {
		data = new byte[1];
		data[0] = (byte) le;
		to = new DERTaggedObject(false, 0x17, new DEROctetString(data));;
	}

	
    	
    public void fromByteArray(byte[] encodedData) {
    	ASN1InputStream asn1in = new ASN1InputStream(encodedData);
    	try {
			to = (DERTaggedObject)asn1in.readObject();
			asn1in.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	DEROctetString ocs = (DEROctetString) to.getObject();
    	data = ocs.getOctets();
    	
    }
    
    
	public byte[] getEncoded() {
    	try {
			return to.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return null;
    }
 

    
    public byte[] getData() {
    	return data;
    }


}
