package de.tsenger.androsmex.pace.paceASN1objects;

import java.math.BigInteger;

import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.HexString;

public class AuthenticationToken {
	
	/**
	 * Der Tag für das Authentication Token Konstrukt. (0x7F49 ist Public Key)
	 */
	private static byte[] tag_ = {(byte)0x7F, (byte)0x49};
	
	
    private DERObjectIdentifier oid06 = null;
    private final BigInteger p81 = null;
    private final BigInteger a82 = null;
    private final BigInteger b83 = null;
    private final ECPoint G84 = null;
    private final BigInteger r85 = null;
    private ECPoint Y86 = null;
    private final BigInteger f87 = null;
    
    private final byte[] token = new byte[8];
    private byte[] x_bytes = null;
    private byte[] y_bytes = null;
    

    //TODO Konstruktor für AuthToken Version 1 implementieren...
    public AuthenticationToken(DERObjectIdentifier oid, 
    		BigInteger primeModulus, 
    		BigInteger firstCoefficient,
    		BigInteger secondCoeffizient,
    		ECPoint basePoint,
    		BigInteger order,
    		ECPoint publicPoint,
    		BigInteger cofactor) {
    	
    	oid06 = oid;
    	Y86 =  publicPoint;
		
		x_bytes = Y86.getX().toBigInteger().toByteArray();
		y_bytes = Y86.getY().toBigInteger().toByteArray();
 	
    }
    
    /** Konstruktor
     * @param oid Algorithm Identifier beeinhaltet die OID des Algorithmus der für PACE verwendet wurde
     * @param publicPoint Domain Parameter des verwendeten PACE-Protokolls 
     */
    public AuthenticationToken(DERObjectIdentifier oid, ECPoint publicPoint) {
    	oid06 = oid;
    	Y86 =  publicPoint;
		x_bytes = Converter.bigIntToByteArray(Y86.getX().toBigInteger());
		y_bytes = Converter.bigIntToByteArray(Y86.getY().toBigInteger());
		
    }
    
    public AuthenticationToken(DERObjectIdentifier oid, BigInteger x, BigInteger y) {
    	oid06 = oid;
		x_bytes = Converter.bigIntToByteArray(x);
		y_bytes = Converter.bigIntToByteArray(y);
		
    }
 	
    
    /** Liefert ein Byte-Array zurück in dem alle Eingangsdaten für die Berechnung des 
     * Authentication Token enthalten sind zurück.
     * @return Byte-Array mit TLV-strukturierten Eingangsdaten
    */
    private byte[] getTokenTLVBytes() {
    	
    	byte[] returndata = null;
    	
    	byte[] pointTLVBytes = new byte[3+x_bytes.length+y_bytes.length];
    	pointTLVBytes[0] = (byte)0x86; //TAG
    	pointTLVBytes[1] = (byte)(x_bytes.length+y_bytes.length+1); // Length
    	pointTLVBytes[2] = (byte) 0x04; // Schon Teil von Value: Uncompressed Point
    	System.arraycopy(x_bytes, 0, pointTLVBytes, 3, x_bytes.length);
    	System.arraycopy(y_bytes, 0, pointTLVBytes, 3+x_bytes.length, y_bytes.length);
    	
		returndata = new byte[3+oid06.getDEREncoded().length+pointTLVBytes.length];
		returndata[0] = tag_[0]; //Tag
		returndata[1] = tag_[1]; //Tag
		returndata[2] = (byte)(oid06.getDEREncoded().length+pointTLVBytes.length); //Length
		System.arraycopy(oid06.getDEREncoded(), 0, returndata, 3, oid06.getDEREncoded().length);
		System.arraycopy(pointTLVBytes, 0, returndata, 3+oid06.getDEREncoded().length, pointTLVBytes.length);
		System.out.println("AuthToken plain data:\n"+HexString.bufferToHex(returndata));
		return returndata;
    }
    
 
    /** Berechnet den CMAC_AES128 über das Authentication Token
     * @param key Byte-Array das den Schlüssel enthült
     * @return Byte-Array mit den ersten 8 Byte des berechneten MACs. Die restlichen Bytes werden abgeschnitten
     */
    private void calculateToken(byte[] key) {
    	byte[] input = getTokenTLVBytes();
    	byte[] output = new byte[16];
    	
    	BlockCipher cipher = new AESFastEngine();
        CMac mac = new CMac(cipher, 128);

        KeyParameter macKey = new KeyParameter(key);
        mac.init(macKey);
        mac.update(input,0,input.length);
        mac.doFinal(output, 0);
        
        System.arraycopy(output, 0, token, 0, 8);
    }
    
    
    public byte[] getToken(byte[] key) {
    	calculateToken(key);
    	return token;
    }
}