package de.tsenger.androsmex.tools;

import java.math.BigInteger;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

public class Converter {
	
	/** Konvertiert ein BigInteger in ein ByteArray. Ein führendes Byte mit dem Wert 0 wird dabei angeschnitten. (Kennzeichen für einen positiven Wert, bei BigIntger)
	 * @param bi Das zu konvertierende BigInteger-Objekt.
	 * @return Byte-Array ohen führendes 0-Byte
	 */
	public static byte[] bigIntToByteArray(BigInteger bi) {
		byte[] temp = bi.toByteArray();
		byte[] returnbytes = null;
		if (temp[0]==0) {
			returnbytes = new byte[temp.length-1];
			System.arraycopy(temp, 1, returnbytes, 0, returnbytes.length);
			return returnbytes;
		}
		else return temp;		
	}
	
	/** Dekodiert aus dem übergebenen Byte-Array einen ECPoint.
	 *  Das benötigte prime field p wird aus der übergebenen Kurve übernommen
	 *  Das erste Byte muss den Wert 0x04 enthalten (uncompressed point).
	 * @param value Byte Array der Form {0x04, x-Bytes[], y-Bytes[]}
	 * @param curve Die Kurve auf der der Punkt liegen soll.
	 * @return Point generiert aus den Input-Daten
	 * @throws Exception Falls das erste Byte nicht den Wert 0x04 enthält, enthält das übergebene Byte-Array offensichtlich keinen Punkt
	 */
	public static ECPoint byteArrayToECPoint(byte[] value, ECCurve.Fp curve) throws Exception {
		byte[] x = new byte[(value.length-1)/2];
		byte[] y = new byte[(value.length-1)/2];
		if (value[0]!=(byte)0x04) throw new Exception("No uncompressed Point found!");
		else {
			System.arraycopy(value, 1, x, 0, (value.length-1)/2);
			System.arraycopy(value, 1+((value.length-1)/2), y, 0, (value.length-1)/2);
			ECFieldElement.Fp xE = new ECFieldElement.Fp(curve.getQ(), new BigInteger(1,x));
			ECFieldElement.Fp yE = new ECFieldElement.Fp(curve.getQ(), new BigInteger(1,y));
			ECPoint point = new ECPoint.Fp(curve, xE, yE);
			return point;
		}
		
	}

}
