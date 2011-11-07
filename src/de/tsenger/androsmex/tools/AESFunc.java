package de.tsenger.androsmex.tools;


import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class AESFunc {
    static byte[] AESCBCConstantIV = HexString.hexToBuffer("0BA0F8DDFEA61FB3D8DF9F566A050F78");
    static byte[] AES_HConstant = HexString.hexToBuffer("2DC2DF39420321D0CEF1FE2374029D95");
    
    static IvParameterSpec IV = new IvParameterSpec(AESCBCConstantIV);
    
    static Cipher AESCBC = null;
    static Cipher AESECB = null;
    
    static{
        try{
            AESCBC = Cipher.getInstance("AES/CBC/NOPADDING");
            AESECB = Cipher.getInstance("AES/ECB/NOPADDING");
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
    
    public static byte[] AESG(byte[] x1, byte[] x2){
        SecretKey AESKey = new SecretKeySpec(x1,0,16,"AES");
        try{
        	synchronized (AESECB) {
	        	AESECB.init(Cipher.DECRYPT_MODE,AESKey);
	        	byte[] out = AESECB.doFinal(x2);
	        	
	        	return(xor(out,x2));
        	}
        } catch(Exception e) {
        	e.printStackTrace();
        }
        
        return(null);
    }
    
    public static byte[] decryptPack(byte[] pack,byte[] contentKey){
        SecretKey AESKey = new SecretKeySpec(contentKey,0,16,"AES");
        
        try{
        	synchronized (AESCBC) {
	        	AESCBC.init(Cipher.DECRYPT_MODE,AESKey,IV);
	        	byte[] result=AESCBC.doFinal(pack);
	        	return(result);
        	}
        } catch(Exception e) {
            e.printStackTrace();
        }
        
        return(null);
    }
    
    public static byte[] encryptAES128(byte[] input,byte[] contentKey){
    	SecretKey AESKey = new SecretKeySpec(contentKey,0,16,"AES");

    	try {
    		synchronized (AESECB) {
    			AESECB.init(Cipher.ENCRYPT_MODE, AESKey);
	    		byte[] result=AESECB.doFinal(input);
	    		return result;
    		}
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
    	
    	return null;
    }
    
    public static byte[] xor(byte[] in1, byte[] in2){
        byte[] out = new byte[in1.length];
        for (int c = 0;c < in1.length; c++){
            out[c] = (byte)((byte)in1[c]^(byte)in2[c]);
        }
        
        return(out);
    }
    
}
