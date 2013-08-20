/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.androsmex.iso7816;

import java.io.ByteArrayOutputStream;
import java.io.IOException;


/**
 * CardCommand stellt einige Standard-ISO7816-CommandAPDU zur Verfügung.
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CardCommands {

	private CardCommands() {
	}
	
	public static CommandAPDU resetRetryCounter(byte passwdRef, byte[] newPasswd) {
		if (!(passwdRef == 2||passwdRef == 3))
			throw new IllegalArgumentException("Invalid password reference! Must be PIN (2) or CAN (3).");
		byte[] cmd = new byte[] { 0, (byte) 0x2C, 0x02, passwdRef };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(cmd);
			command.write(newPasswd.length);
			command.write(newPasswd);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU readBinary(byte sfid, byte readlength) {
		if (sfid > 0x1F)
			throw new IllegalArgumentException("Invalid Short File Identifier!");
		byte P1 = (byte) 0x80;
		P1 = (byte) (P1 | sfid);
		return new CommandAPDU(new byte[] { 0, (byte) 0xB0, P1, 0, readlength });
	}

	public static CommandAPDU readBinary(byte high_offset, byte low_offset,
			byte le) {
		byte[] command = { (byte) 0x00, (byte) 0xB0, high_offset, low_offset,
				le };
		return new CommandAPDU(command);
	}

	public static CommandAPDU selectEF(byte[] fid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x02,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(fid.length);
			command.write(fid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

	public static CommandAPDU selectApp(byte[] aid) {
		byte[] selectCmd = new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x04,
				(byte) 0x0C };
		ByteArrayOutputStream command = new ByteArrayOutputStream();
		try {
			command.write(selectCmd);
			command.write(aid.length);
			command.write(aid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}

}

