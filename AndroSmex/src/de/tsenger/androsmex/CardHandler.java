package de.tsenger.androsmex;


public interface CardHandler {
	
	public ResponseAPDU sendCommandAPDU(CommandAPDU cmd) throws Exception;

	public boolean isConnected();
}
