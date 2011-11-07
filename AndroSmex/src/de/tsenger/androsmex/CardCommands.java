package de.tsenger.androsmex;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

import de.tsenger.androsmex.bac.SecureMessaging;
import de.tsenger.androsmex.tools.HexString;

public class CardCommands {
	
	private CardHandler ch = null;
	private SecureMessaging sm = null;

	public CardCommands(CardHandler ch, SecureMessaging sm) {
		this.ch = ch;
		this.sm = sm;
	}
	

	public ResponseAPDU readBinary(byte sfid, byte readlength) throws Exception {
		if (sfid>0x1F) throw new Exception("Invalid Short File Identifier!");
		byte P1 = (byte) 0x80;
		P1=(byte) (P1|sfid);
		CommandAPDU capdu = new CommandAPDU(5);
		capdu.append(new byte[] {0, (byte)0xB0, P1, 0, readlength});
		if (sm!=null) {
			CommandAPDU scapdu = sm.encodeCommandAPDU(capdu);
			ResponseAPDU encrsp = ch.sendCommandAPDU(scapdu);
			ResponseAPDU decrsp = sm.decodeResponseAPDU(encrsp);
			return decrsp;
		} else {
			return ch.sendCommandAPDU(capdu);
		}
	}
	
	private ResponseAPDU readBinary(byte high_offset, byte low_offset, byte le) throws Exception{        
        byte[] command = {(byte)0x00, (byte)0xB0, high_offset, low_offset, le};
        CommandAPDU capdu = new CommandAPDU(5);
        capdu.append(command);
        if (sm!=null) {
			CommandAPDU scapdu = sm.encodeCommandAPDU(capdu);
			ResponseAPDU encrsp = ch.sendCommandAPDU(scapdu);
			ResponseAPDU decrsp = sm.decodeResponseAPDU(encrsp);
			return decrsp;
		} else {
			return ch.sendCommandAPDU(capdu);
		}         
    }
	
	public byte[] getFile(byte sfid) throws Exception {
		if (sfid>0x1F) throw new Exception("Invalid Short File Identifier!");
		
		ResponseAPDU resp = readBinary(sfid, (byte)0x08);
		if (resp.sw1()!=(byte)0x90) throw new Exception("Can't read File (SFI: "+sfid+"). SW: "+HexString.bufferToHex(resp.sw()));
		int remainingBytes = getLength(resp.data());
		byte[] fileData = new byte[remainingBytes];
		
		int maxReadLength = 0xF0;	
		int i = 0;
		
        do {
        	int offset = i*maxReadLength;
    		byte off1 = (byte) ((offset & 0x0000FF00) >> 8);
    		byte off2 = (byte) (offset & 0x000000FF);
    		
        	if (remainingBytes <= maxReadLength) {
        		resp = readBinary((byte) off1, (byte) off2, (byte) remainingBytes);
        		remainingBytes = 0;
        	}
        	else {
        		resp = readBinary((byte) off1, (byte) off2, (byte) maxReadLength);
        		remainingBytes =- maxReadLength;
        	}
            System.arraycopy(resp.data(),0,fileData,i*maxReadLength,resp.data().length);
            i++;
            
           
        } while (remainingBytes>0);
        return fileData;
	}

	private int getLength(byte[] b) throws IOException {
		ByteArrayInputStream s = new ByteArrayInputStream(b);
		int size=0;
		s.read();
		int length = s.read();
		if (length < 0)
			throw new EOFException("EOF found when length expected");

		if (length == 0x80)
			return -1; // indefinite-length encoding

		if (length > 127) {
			size = length & 0x7f;

			// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be
			// caught here
			if (size > 4)
				throw new IOException("DER length more than 4 bytes: " + size);

			length = 0;
			for (int i = 0; i < size; i++) {
				int next = s.read();
				if (next < 0) 
					throw new EOFException("EOF found reading length");
				length = (length << 8) + next;
			}

			if (length < 0)
				throw new IOException("corrupted stream - negative length found");

		}
		return length+size+2; // +1 Tag, +1 Längenangabe
	}

}
