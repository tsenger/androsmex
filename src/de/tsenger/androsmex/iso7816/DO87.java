package de.tsenger.androsmex.iso7816;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;



public class DO87 {
	
    private byte[] value_ = null;
    private byte[] data = null;
    private DERTaggedObject to = null;

    public DO87() {}
    
	public DO87(byte[] data) {
		this.data = data.clone();
		value_ = addOne(data);
		to = new DERTaggedObject(false, 7, new DEROctetString(value_));
	}

	private  byte[] addOne(byte[] data) {
		byte[] ret = new byte[data.length+1];
		System.arraycopy(data, 0, ret, 1, data.length);
		ret[0] = 1;
		return ret;
	}
	
	private byte[] removeOne(byte[] value) {
		byte[] ret = new byte[value.length-1];
		System.arraycopy(value, 1, ret, 0, ret.length);
		return ret;
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
		value_ = ocs.getOctets();
		data = removeOne(value_);
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
