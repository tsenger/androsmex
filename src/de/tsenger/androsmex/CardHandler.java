package de.tsenger.androsmex;

import java.io.IOException;

import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessagingException;


public interface CardHandler {
	
	public ResponseAPDU transceive(CommandAPDU cmd) throws IOException, SecureMessagingException;
	
	public int getMaxTranceiveLength();

	public boolean isConnected();
}
