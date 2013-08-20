/**
 * 
 */
package de.tsenger.androsmex.iso7816;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DO8E {
	
    private byte[] data = null;
    private DERTaggedObject to = null;
    
	
	public DO8E(){}
	

	public DO8E(byte[] checksum){
		data = checksum.clone();
		to = new DERTaggedObject(false, 0x0E, new DEROctetString(checksum));
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
