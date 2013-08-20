package de.tsenger.androsmex.tools;

import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

public class Converter {
	
	
	public static Date BCDtoDate(byte[] yymmdd) {
		if( yymmdd==null || yymmdd.length!=6 ){
	         throw new IllegalArgumentException("Argument must have length 6, was " + (yymmdd==null?0:yymmdd.length));
	      }
		int year  = 2000 + yymmdd[0]*10 + yymmdd[1];
	    int month = yymmdd[2]*10 + yymmdd[3] - 1; // Java month index starts with 0...
	    int day   = yymmdd[4]*10 + yymmdd[5];
		GregorianCalendar gregCal = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
		gregCal.set(year, month, day,0,0,0);
		return gregCal.getTime();
	}

	/**
	 * Converts a byte into a unsigned integer value.
	 * 
	 * @param value
	 * @return
	 */
	public static int toUnsignedInt(byte value) {
		return (value & 0x7F) + (value < 0 ? 128 : 0);
	}

	public static long ByteArrayToLong(byte[] bytes) {

		long lo = 0;
		for (int i = 0; i < 8; i++) {
			lo <<= 8;
			lo += (bytes[i] & 0x000000FF);
		}
		return lo;
	}

	/**
	 * Writes a <code>long</code> to byte array as sixteen bytes, high byte
	 * first.
	 * 
	 * @param v
	 *            a <code>long</code> to be converted.
	 */
	public static byte[] longToByteArray(long v) {
		byte[] ivByes = new byte[8];
		ivByes[0] = (byte) (v >>> 56);
		ivByes[1] = (byte) (v >>> 48);
		ivByes[2] = (byte) (v >>> 40);
		ivByes[3] = (byte) (v >>> 32);
		ivByes[4] = (byte) (v >>> 24);
		ivByes[5] = (byte) (v >>> 16);
		ivByes[6] = (byte) (v >>> 8);
		ivByes[7] = (byte) (v >>> 0);
		return ivByes;
	}

	/**
	 * Konvertiert ein BigInteger in ein ByteArray. Ein führendes Byte mit dem
	 * Wert 0 wird dabei angeschnitten. (Kennzeichen für einen positiven Wert,
	 * bei BigIntger)
	 * 
	 * @param bi
	 *            Das zu konvertierende BigInteger-Objekt.
	 * @return Byte-Array ohne führendes 0-Byte
	 */
	public static byte[] bigIntToByteArray(BigInteger bi) {
		byte[] temp = bi.toByteArray();
		byte[] returnbytes = null;
		if (temp[0] == 0) {
			returnbytes = new byte[temp.length - 1];
			System.arraycopy(temp, 1, returnbytes, 0, returnbytes.length);
			return returnbytes;
		} else
			return temp;
	}

	/**
	 * Dekodiert aus dem übergebenen Byte-Array einen ECPoint. Das benötigte
	 * prime field p wird aus der übergebenen Kurve übernommen Das erste Byte
	 * muss den Wert 0x04 enthalten (uncompressed point).
	 * 
	 * @param value
	 *            Byte Array der Form {0x04 || x-Bytes[] || y-Bytes[]}
	 * @param curve
	 *            Die Kurve auf der der Punkt liegen soll.
	 * @return Point generiert aus den Input-Daten
	 * @throws IllegalArgumentException
	 *             Falls das erste Byte nicht den Wert 0x04 enthält, enthält das
	 *             übergebene Byte-Array offensichtlich keinen unkomprimierten Punkt
	 */
	public static ECPoint byteArrayToECPoint(byte[] value, ECCurve.Fp curve)
			throws IllegalArgumentException {
		byte[] x = new byte[(value.length - 1) / 2];
		byte[] y = new byte[(value.length - 1) / 2];
		if (value[0] != (byte) 0x04)
			throw new IllegalArgumentException("No uncompressed Point found!");
		else {
			System.arraycopy(value, 1, x, 0, (value.length - 1) / 2);
			System.arraycopy(value, 1 + ((value.length - 1) / 2), y, 0,
					(value.length - 1) / 2);
			ECFieldElement.Fp xE = new ECFieldElement.Fp(curve.getQ(),
					new BigInteger(1, x));
			ECFieldElement.Fp yE = new ECFieldElement.Fp(curve.getQ(),
					new BigInteger(1, y));
			ECPoint point = new ECPoint.Fp(curve, xE, yE);
			return point;
		}

	}

}
