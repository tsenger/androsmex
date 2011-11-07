package de.tsenger.androsmex;

import java.io.IOException;

public interface CardHandler {
	
	public ResponseAPDU sendCommandAPDU(CommandAPDU cmd) throws Exception;

	public boolean isConnected();
}
