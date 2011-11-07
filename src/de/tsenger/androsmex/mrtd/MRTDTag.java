package de.tsenger.androsmex.mrtd;

import java.io.IOException;

import de.tsenger.androsmex.CardHandler;
import de.tsenger.androsmex.CommandAPDU;
import de.tsenger.androsmex.ResponseAPDU;
import de.tsenger.androsmex.bac.BACFunctions;
import de.tsenger.androsmex.bac.SecureMessaging;
import de.tsenger.androsmex.pace.paceASN1objects.SecurityInfos_bc;

public class MRTDTag  {
	
//	private CommandAPDU command = null;
//	private ResponseAPDU response = null;
	
	private String mrz = null;
	private final byte[] MRTD_AID = new byte[] {(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x47, (byte)0x10, (byte)0x01};
	
	private CardHandler card = null;
	private BACFunctions bac = null;
	private SecureMessaging sm = null;
	
	private boolean bac_established = false;
	
	private DG2 dg2 = null;
	
	
	
	
	public MRTDTag(CardHandler card, String mrz) {
		this.card = card;
		this.mrz = mrz;
	}
	
	//Liest momentan einfach nur maximal 255 Bytes aus...
	//TODO erweitern damit, größere Datengruppen gelesen werden können.
	public byte[] readBinary(byte sfid) throws Exception {
		byte P1 = (byte) 0x80;
		P1=(byte) (P1|sfid);
		CommandAPDU capdu = new CommandAPDU(5);
		capdu.append(new byte[] {0, (byte)0xB0, P1, 0, 0});
		if (bac_established) {
			CommandAPDU scapdu = sm.encodeCommandAPDU(capdu);
			ResponseAPDU encrsp = card.sendCommandAPDU(scapdu);
			ResponseAPDU decrsp = sm.decodeResponseAPDU(encrsp);
			return decrsp.getBytes();
		} else {
			return card.sendCommandAPDU(capdu).getBytes();
		}
	}
	
	//Liest momentan einfach nur maximal 255 Bytes aus... readlength wird nicht beachtet
	//TODO erweitern damit, größere Datengruppen gelesen werden können.
	public ResponseAPDU readBinary(byte sfid, byte readlength) throws Exception {
		byte P1 = (byte) 0x80;
		P1=(byte) (P1|sfid);
		CommandAPDU capdu = new CommandAPDU(5);
		capdu.append(new byte[] {0, (byte)0xB0, P1, 0, 0});
		if (bac_established) {
			CommandAPDU scapdu = sm.encodeCommandAPDU(capdu);
			ResponseAPDU encrsp = card.sendCommandAPDU(scapdu);
			ResponseAPDU decrsp = sm.decodeResponseAPDU(encrsp);
			return decrsp;
		} else {
			return card.sendCommandAPDU(capdu);
		}
	}
	
	private ResponseAPDU readBinary(byte high_offset, byte low_offset, byte le) throws Exception{        
        byte[] command = {(byte)0x00, (byte)0xB0, high_offset, low_offset, le};
        CommandAPDU capdu = new CommandAPDU(5);
        capdu.append(command);
        if (bac_established) {
			CommandAPDU scapdu = sm.encodeCommandAPDU(capdu);
			ResponseAPDU encrsp = card.sendCommandAPDU(scapdu);
			ResponseAPDU decrsp = sm.decodeResponseAPDU(encrsp);
			return decrsp;
		} else {
			return card.sendCommandAPDU(capdu);
		}         
    }
	
	public DG2 getDG2() throws Exception {
        
        if (dg2!=null) return dg2;
        ResponseAPDU resp = readBinary((byte)0x02, (byte)0x08);
        int dg2Length = (JSmexTools.toUnsignedInt(resp.data()[2])*256+JSmexTools.toUnsignedInt(resp.data()[3])+4);
        
        int i = 0;
        byte[] dg2Data = new byte[dg2Length];
     
        do {
        	resp = readBinary((byte) i, (byte) 0, (byte) 0x100);
            if (resp.data()==null) break;
            System.arraycopy(resp.data(),0,dg2Data,i*0x100,resp.data().length);
            i++;
           
        } while (resp.sw1()==(byte)0x90);
        
        dg2 = new DG2(dg2Data);
        return dg2;
    }
	
	
	
	public SecurityInfos_bc getEFCardAccess() throws Exception {
		
		SecurityInfos_bc efCardAccess = new SecurityInfos_bc();
		ResponseAPDU resp = readBinary((byte)0x1C, (byte)0x08);
        int dgLength = (JSmexTools.toUnsignedInt(resp.data()[2])*256+JSmexTools.toUnsignedInt(resp.data()[3])+4);
        
        int i = 0;
        byte[] caData = new byte[dgLength];
     
        do {
        	resp = readBinary((byte) i, (byte) 0, (byte) 0x100);
            if (resp.data()==null) break;
            System.arraycopy(resp.data(),0,caData,i*0x100,resp.data().length);
            i++;
           
        } while (resp.sw1()==(byte)0x90);
        
        efCardAccess.decode(caData);
        return efCardAccess;
    }
	
	/** Führt BAC durch
	 * @return true when BAC erfolgreich durchgeführt wurde, ansonsten false
	 * @throws Exception
	 */
	public boolean performBAC() throws Exception {
		selectAID(MRTD_AID);
		byte[] challenge = getCardChallenge().data();
		if (challenge!=null) {
			bac = new BACFunctions(mrz, challenge);
			byte[] mu_data = bac.getMutualAuthenticationCommand();
			byte[] mu_resp = sendMutualAuthenticate(mu_data).data();
			if (mu_resp!=null) {
				sm = bac.establishBAC(mu_resp);
				bac_established = (sm==null)?false:true;
			} else return false;
		}
		else return false;
		return bac_established;
	}
	
	private ResponseAPDU selectAID(byte[] aid)
	{
		CommandAPDU capdu = new CommandAPDU(30); //Select MRTD_AID command
		capdu.append(new byte[] { (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x0C});
		capdu.append((byte)aid.length);
		capdu.append(aid);
		ResponseAPDU rapdu = null;
		try {
			rapdu = card.sendCommandAPDU(capdu);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		return rapdu;
	}

	
	/**
	 * Sendet eine getChallenge CommandAPDU zum CardHandler
	 * 
	 * @return ResponseAPDU enthält RND.ICC
	 *         
	 * @throws IOException
	 */
	private ResponseAPDU getCardChallenge() throws Exception {

		byte[] cmd = { (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0x00,
				(byte) 0x08 };
		ResponseAPDU rapdu = null;
		CommandAPDU command = new CommandAPDU(25);
		command.append(cmd);

		rapdu = card.sendCommandAPDU(command);

		return rapdu;
		//return new ResponseAPDU(new byte[]{(byte)0x46, (byte)0x08, (byte)0xF9, (byte)0x19,
		// (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12});
	}
	
	/**
	 * Sendet das Kommando MUTUAL AUHTENTICATION mit den übergebenen Daten zur
	 * Karte.
	 * 
	 * @param data
	 *            Byte-Array welches E_ifd und M_ifd enthält
	 * @return ResponseAPDU enthält SW und ggf. Rückgabedaten
	 * @throws Exception
	 *             When the mutual authentication command fails a exception is
	 *             thrown
	 */
	private ResponseAPDU sendMutualAuthenticate(byte[] data) throws Exception {

		byte[] ma_cmd = { (byte) 0x00, (byte) 0x82, (byte) 0x00, (byte) 0x00,
				(byte) (data.length) };
		CommandAPDU command = new CommandAPDU(46);
		command.append(ma_cmd);
		command.append(data);
		command.append((byte) 0x28); // LE = 0x28 (40 dec)
		
		return card.sendCommandAPDU(command);
		 
	}

}
