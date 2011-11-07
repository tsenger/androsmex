package de.tsenger.androsmex.pace.paceASN1objects;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import ext.org.bouncycastle.asn1.ASN1InputStream;
import ext.org.bouncycastle.asn1.ASN1OutputStream;
import ext.org.bouncycastle.asn1.DEREncodable;
import ext.org.bouncycastle.asn1.DEROctetString;
import ext.org.bouncycastle.asn1.DERTaggedObject;



public class MappingData81 extends DERTaggedObject{
	
	private static final byte[] DEFAULT_VALUE = new byte[0];
    private byte[] value_ = DEFAULT_VALUE;
    DERTaggedObject to = null;
    DEROctetString ocs = null;
	
    //Konstruktor zum Decoden
	public MappingData81(){
		super(1);
	}
	
	//Konstruktor zum Encoden
	public MappingData81(byte[] data) {
		super(false, 0x01, new DEROctetString(data));
	}

	
    	
    public void decode(byte[] encodedData) {
    	ASN1InputStream asn1in = new ASN1InputStream(encodedData);
    	try {
			to = (DERTaggedObject)asn1in.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ocs = (DEROctetString) to.getObject();
		value_ = ocs.getOctets();
    }
 

    
    public byte[] getData() {
    	return value_;
    }


}
