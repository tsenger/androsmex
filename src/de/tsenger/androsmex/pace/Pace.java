/**
 * 
 */
package de.tsenger.androsmex.pace;



/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public abstract class Pace {
	
	protected byte[] nonce_s = null;
	protected byte[] sharedSecret_P = null;
	protected byte[] sharedSecret_K = null;
	
	/**
	 * Berechnet das erste KeyPair. x1: privater Schlüssel (Zufallszahl) und 
	 * X1: öffentlicher Schlüssel.
	 * 	 
	 * @param s Die enschlüsselte nonce s der Karte
	 * @return Der erste öffentliche Schlüssel X1 des Terminals.
	 */
	public abstract byte[] getX1(byte[] s);
	
	
	/**
	 * Berechnet mit Hilfe des öffentlichen Schlüssels der Karte das erste
	 * Shared Secret P und den zweiten öffentlichen Schlüssel des Terminals
	 * 
	 * @param Y1 Erster öffentlicher Schlüssel der Karte.
	 * @return Zweiter öffentlicher Schlüssel X2 des Terminals.
	 */
	public abstract byte[] getX2(byte[] Y1);
	
	
	/**
	 * Erzeugt das finale Shared Secret K
	 * 
	 * @param Y2 Zweiter öffentlicher Schlüssel Y2 der Karte
	 * 
	 */
	public abstract byte[] getSharedSecret_K(byte[] Y2);
	


}
