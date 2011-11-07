package de.tsenger.androsmex.bac;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.tsenger.androsmex.CommandAPDU;
import de.tsenger.androsmex.ResponseAPDU;
import de.tsenger.androsmex.tools.Crypto;

public class SecureMessaging{
	
	private byte[] ks_enc = null;
	private byte[] ks_mac = null;
	private byte[] ssc = null;
	
	/** Konstruktor 
	 * @param ksenc Session Key für Verschlüsselung (K_enc)
	 * @param ksmac Session Key für Prüfsummenberechnung (K_mac)
	 * @param initssc Initialer Wert des Send Sequence Counters
	 */
	public SecureMessaging(byte[] ksenc, byte[] ksmac, byte[] initssc) {
		ks_enc = ksenc.clone();
		ks_mac = ksmac.clone();
		ssc = initssc.clone();
	}
		
	/**Erzeugt aus einer Command-APDU ohne Secure Messaging eine Command-APDU mit Secure Messaging.
	 * 
	 * @param capdu Ungeschützte Command-APDU
	 * @return CommandAPDU mit SM
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public CommandAPDU encodeCommandAPDU(CommandAPDU capdu) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        
		byte[] header = null;
		byte lc = 0;
		byte[] paddedheader = null;
		byte[] do97 = null;
		byte[] do87 = null;
		byte[] do8E = null;
		byte[] m = null;
		
        // Mask class byte and pad command header
		header = capdu.header().clone();
		header[0] = (byte)(header[0]|(byte)0x0C);
        paddedheader = Crypto.padByteArray(header);        
        
        // build DO87
        if (capdu.getAPDUStructure()==3||capdu.getAPDUStructure()==4) {
        	do87 = buildDO87(capdu.data().clone());
        	lc+=do87.length;
        }
        
        // build DO97
        if (capdu.getAPDUStructure()==2||capdu.getAPDUStructure()==4) {
        	do97 = buildDO97(capdu.le());
        	lc+=do97.length;
        }
                
        // M wird zur Berechnung des DO8E benötigt.
        if (do97==null&&do87==null) {
        	m = new byte[paddedheader.length];
        	System.arraycopy(paddedheader, 0, m, 0, paddedheader.length);
        } else if (do97!=null&&do87==null) {
        	m=new byte[paddedheader.length+do97.length];
        	System.arraycopy(paddedheader, 0, m, 0, paddedheader.length);
        	System.arraycopy(do97, 0, m, paddedheader.length, do97.length);
        } else if (do97==null&&do87!=null) {
        	m=new byte[paddedheader.length+do87.length];
        	System.arraycopy(paddedheader, 0, m, 0, paddedheader.length);
        	System.arraycopy(do87, 0, m, paddedheader.length, do87.length);
        } else if (do97!=null&&do87!=null) {
        	m=new byte[paddedheader.length+do87.length+do97.length];
        	System.arraycopy(paddedheader, 0, m, 0, paddedheader.length);
        	System.arraycopy(do87, 0, m, paddedheader.length, do87.length);
        	System.arraycopy(do97, 0, m, paddedheader.length+do87.length, do87.length);
        }
                
        // build DO8E
        do8E = buildDO8E(m);
        lc+=do8E.length;
        
        // construct and return protected APDU
        CommandAPDU command = new CommandAPDU(150);
        command.append(header);
        command.append((byte)lc);
        if (do87!=null) command.append(do87);
        if (do97!=null) command.append(do97);
        command.append(do8E);
        command.append((byte)0x00);
        return command;
    }
	
	public ResponseAPDU decodeResponseAPDU (ResponseAPDU rapdu) throws Exception {
	       
        byte[] responseData = null;
        byte[] decryptedData = null;
        int  pointer = 0;
        
        // Check checksums of response
        if (verifyRAPDU(rapdu.data())) {
            
            // extract the DO87
            byte[] do87 = extractDO((byte)0x87, rapdu.data(), pointer);
            if (do87!=null) {
                byte[] encryptedData = extractDOdata(do87);
                decryptedData = Crypto.tripleDES(false, ks_enc,encryptedData);
                decryptedData = Crypto.removePadding(decryptedData);
                pointer = pointer+do87.length;
            }
            
            // extract the DO99
            byte[] do99 = extractDO((byte)0x99, rapdu.data(), pointer);
            byte[] sw = extractDOdata(do99);
            
            // if there was no data, only return the SW
            if (do87!=null) {
            	responseData = mergeByteArray(decryptedData, sw);
            }
            else responseData = sw.clone();
            
        }
        else {
            throw new Exception("Checksum incorrect!");
        }
        return new ResponseAPDU(responseData);
    }
	
	/** Merge two byte array to a new big one.
    *
    * @param a1 Source array 1
    * @param a2 Source array 2
    * @return New byte array which contains data from the two source arrays.
    */
   private byte[] mergeByteArray(byte[] a1, byte[] a2) {
       byte[] newArray = new byte[ a1.length + a2.length ];
       System.arraycopy( a1, 0, newArray, 0, a1.length );
       System.arraycopy( a2, 0, newArray, a1.length, a2.length );
       return newArray;
   }

	/**
     * Checks the checksum of the given Response APDU
     * @param rapdu The RepsonseAPDU
     * @return Returns true if checksum is correct, otherwise this method returns a false
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
     */
    private boolean verifyRAPDU(byte[] rapdu) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        int pointer = 0;        
        
        // extract the DO87
        byte[] do87 = extractDO((byte)0x87, rapdu, pointer);        
        
        if (do87!=null) pointer = pointer+do87.length; 
                
        // extract the DO99
        byte[] do99 = extractDO((byte)0x99, rapdu, pointer);
        
        if (do87!=null) pointer = pointer+do99.length; 
        
        // extract the DO8E
        byte[] do8E = extractDO((byte)0x8E, rapdu, pointer);
        
        ssc = incByteArray(ssc);
        
        byte[] k = null; 
        
        if (do87!=null) {
            k = mergeByteArray(ssc, do87);
            k = mergeByteArray(k, do99);
        }
        else k = mergeByteArray(ssc, do99);        
                
        //compute MAC with KSMAC
        byte[] cc2 = Crypto.computeMAC(ks_mac, k);
        
        //compare cc' with data of DO8E of RAPDU
        if (Arrays.equals(cc2,extractDOdata(do8E))) return true;
        else return false;
    }
    
    private byte[] extractDOdata(byte[] dataObject) {
        byte[] data = null;
        if (dataObject[0]==(byte)0x87) {
            
            int len = asn1DataLength(dataObject,0);
                      
            int startIndex = 0;
            if (toUnsignedInt(dataObject[1]) <= 0x7F) startIndex=3;
            else if (toUnsignedInt(dataObject[1]) == 0x81) startIndex=4;
            else if (toUnsignedInt(dataObject[1]) == 0x82) startIndex=5;
            data = new byte[len-1];
            System.arraycopy(dataObject,startIndex,data,0,data.length);
        }
        else {
            data = new byte[toUnsignedInt(dataObject[1])];
            System.arraycopy(dataObject,2,data,0,data.length);
        }
        return data;
    }
    
    private int asn1DataLength(byte[] asn1Data, int startByte) {
        if (toUnsignedInt(asn1Data[(startByte+1)]) <= 0x7f) 
            return toUnsignedInt(asn1Data[(startByte+1)]);
        
        if (toUnsignedInt(asn1Data[(startByte+1)]) == 0x81) 
            return toUnsignedInt(asn1Data[(startByte+2)]);
        
        if (toUnsignedInt(asn1Data[(startByte+1)]) == 0x82) 
            return (toUnsignedInt(asn1Data[(startByte+2)])*256+toUnsignedInt(asn1Data[(startByte+3)]));
        
	return 0;
    }
    
    /**Converts a byte into a unsigned integer value.
    *
    * @param value
    * @return
    */
   private int toUnsignedInt(byte value) {
       return (value & 0x7F) + (value < 0 ? 128 : 0);
   }
    
    private byte[] extractDO(byte doID, byte[] rapdu, int startByte) {
        for (int i = startByte;i<rapdu.length;i++) {
            if (rapdu[i]==doID) {
                int len = asn1DataLength(rapdu.clone(), i);
                
                int addlen = 2;
                if (rapdu[i+1] == (byte)0x81) addlen = 3;
                else if (rapdu[i+1] == (byte)0x82) addlen = 4;
                
                byte[] dataObject = new byte[(len+addlen)];
                
                System.arraycopy(rapdu,i,dataObject,0,dataObject.length);
                
                return dataObject;
            }
        }
        return null;
    }
	
	//Pad data, encrypt data with KS.ENC and build DO87
    private byte[] buildDO87(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        //b
        data = Crypto.padByteArray(data);
        
        //c
        byte[] encrypted_data = Crypto.tripleDES(true, ks_enc, data);
        
        //d
        byte[] do87 = new byte[encrypted_data.length+3];
        byte[] header = new byte[]{(byte)0x87, (byte)(encrypted_data.length+1), (byte)0x01};
        System.arraycopy(header,0,do87,0,header.length);
        System.arraycopy(encrypted_data,0,do87,3,encrypted_data.length);
        return do87;
    }
	
	private byte[] buildDO8E(byte[] m) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] cc = buildCC(m);        
        byte[] do8E = new byte[cc.length+2];
        byte[] header = new byte[]{(byte)0x8E, (byte)(cc.length)};
        System.arraycopy(header,0,do8E,0,header.length);
        System.arraycopy(cc,0,do8E,2,cc.length);
        return do8E;
    }
	
	private byte[] buildDO97(byte le) {
        return new byte[]{(byte)0x97, (byte)0x01, le};
    }
	
    // Build MAC of data
    private byte[] buildCC(byte[] m) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
                
        ssc = incByteArray(ssc);
        byte[] n = new byte[ssc.length+m.length];
        System.arraycopy(ssc,0,n,0,ssc.length);
        System.arraycopy(m,0,n,ssc.length,m.length);
        byte[] cc = Crypto.computeMAC(ks_mac, n);
        return cc;
    }
    
    private byte[] incByteArray(byte[] array) {
        for (int i=array.length-1;i>=1;i--) {
            if (array[i] == (byte)0xFF) {
                array[i] = (byte)0x00;
            }
            else {
                byte a = array[i];
                a++;
                array[i] = a; 
                return array;
            }
        }
        return array;
    }

}
