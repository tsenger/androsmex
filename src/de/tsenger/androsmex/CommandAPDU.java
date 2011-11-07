package de.tsenger.androsmex;


public class CommandAPDU {
	
	public static final byte CASE1_CAPDU = 1;
	public static final byte CASE2S_CAPDU = 2;
	public static final byte CASE3S_CAPDU = 3;
	public static final byte CASE4S_CAPDU = 4;
	public static final byte CASE2E_CAPDU = 5;
	public static final byte CASE3E_CAPDU = 6;
	public static final byte CASE4E_CAPDU = 7;
	
	private byte capdustructure = 0;
	
	private byte[] header = null;
	private byte le = 0;
	private byte[] le_extended = null;
	private byte lc = 0;
	private byte[] lc_extended = null;
	private byte[] data = null;
	
	private byte[] cardcmd = null;
	private byte[] cmdraw = null;
	private int pointer = 0;
	
	public CommandAPDU(int size){
		cmdraw = new byte[size];
	}
	
	/** Fügt der CommandAPDU weitere Daten hinzu
	 * @param data Byte-Array mit Daten
	 */
	public void append(byte[] data) {
		if (data==null) return;
		if (pointer+data.length<=cmdraw.length) {
			for (int i = 0;i<data.length;i++){
				cmdraw[pointer+i] = data[i];
			}
			pointer+=data.length;
		}
	}
	
	/** Fügt der CommandAPDU weitere Daten hinzu
	 * @param data Byte mit Daten
	 */
	public void append(byte data) {
		if (pointer+1<=cmdraw.length) {
			cmdraw[pointer] = data;
			pointer++;
		}
	}
	
	/** Liefert den Inhalt der CAPDU zurück.
	 * @return Der Inhalt der CAPDU hat die Länge der insgesamt hinzugefügten Daten auch wenn die CommandAPDU gr��er angelegt wurde.
	 */
	public byte[] getBytes() {
		cardcmd = new byte[pointer];
		for (int i = 0;i<pointer;i++) {
			cardcmd[i] = cmdraw[i];
		}
		return cardcmd;
	}
	
	/** Liefert den header der APDU zurück.
	 * @return header
	 */
	public byte[] header() {
		if (capdustructure==0) getAPDUStructure(); 
		//System.out.println("Header: "+HexString.bufferToHex(header));
		return header;
	}
	

	/** Falls CASE3S_APDU, CASE4S_APDU, CASE3E_APDU oderCASE4E_APDU wird der Wert für "data" zurückgeliefert. 
	 * @return Byte mit data
	 */
	public byte[] data() {
		if (capdustructure==0) getAPDUStructure();
		//System.out.println("Data: "+HexString.bufferToHex(data));
		return data;
	}
	
	/** Falls CASE3S_APDU oder CASE4S_APDU wird der Wert für "length command" zurückgeliefert. 
	 * @return Byte mit Lc Wert
	 */
	public byte lc() {
		if (capdustructure==0) getAPDUStructure();
		//System.out.println("Lc: "+lc);
		return lc;
	}
	
	/** Falls CASE2S_APDU oder CASE4S_APDU wird der Wert für "length expected" zurückgeliefert. 
	 * @return Byte mit Le Wert
	 */
	public byte le() {
		if (capdustructure==0) getAPDUStructure();
		//System.out.println("Le: "+le);
		return le;
	}
	
	/** Falls CASE3E_APDU oder CASE4E_APDU wird der Wert für "length command" zurückgeliefert. 
	 * @return Byte-Array mit den Lc Daten
	 */
	public byte[] lc_extended() {
		if (capdustructure==0) getAPDUStructure();
		//System.out.println("Lc_extended: "+HexString.bufferToHex(lc_extended));
		return lc_extended;
	}
	
	/** Falls CASE2E_APDU oder CASE4E_APDU wird der Wert für "length expected" zurückgeliefert. 
	 * @return Byte-Array mit den Le Daten
	 */
	public byte[] le_extended() {
		if (capdustructure==0) getAPDUStructure();
		//System.out.println("Le_extended: "+HexString.bufferToHex(le_extended));
		return le_extended;
	}
	
	/** Strukturiert die fertige APDU und bestimmt, header, Le, Lc, und Daten soweit vorhanden.
	 * Zudem wird bestimmt welchem Case die CAPDU enstpricht. (Siehe ISO/IEC 7816-3 Kapitel 12.1)
	 * @return Strukurtype (1 = CASE1, ...)
	 */
	public byte getAPDUStructure() {
		byte[] cardcmd = getBytes();

		// Der header sind immer die ersten vier Bytes der C-APDU;
		header = new byte[4];
		System.arraycopy(cardcmd, 0, header, 0, 4);
				
		if (cardcmd.length==4) return CASE1_CAPDU;
		if (cardcmd.length==5) {
			le = cardcmd[4];
			return CASE2S_CAPDU;
		}
		if (cardcmd.length==(5+cardcmd[4]) && cardcmd[4]!=0) {
			lc = cardcmd[4];
			data = new byte[lc];
			System.arraycopy(cardcmd, 5, data, 0, lc);		
			return CASE3S_CAPDU;
		}
		if (cardcmd.length==(6+cardcmd[4]) && cardcmd[4]!=0) {
			lc = cardcmd[4];
			data = new byte[lc];
			System.arraycopy(cardcmd, 5, data, 0, lc);
			le = cardcmd[5+lc];
			return CASE4S_CAPDU;
		}
		if (cardcmd.length==7 && cardcmd[4]==0) {
			le_extended = new byte[] {cardcmd[4], cardcmd[5], cardcmd[6]};
			return CASE2E_CAPDU;
		}
		if (cardcmd.length==(7+cardcmd[5]*256+cardcmd[6]) && cardcmd[4]==0 && (cardcmd[5]!=0 || cardcmd[6]!=0)) {
			lc_extended = new byte[] {cardcmd[4], cardcmd[5], cardcmd[6]};
			data = new byte[lc_extended[1]*256+lc_extended[2]];
			System.arraycopy(cardcmd, 7, data, 0, (lc_extended[1]*256+lc_extended[2]));
			return CASE3E_CAPDU;
		}
		
		if (cardcmd.length==(9+cardcmd[5]*256+cardcmd[6]) && cardcmd[4]==0 && (cardcmd[5]!=0 || cardcmd[6]!=0)) {
			lc_extended = new byte[] {cardcmd[4], cardcmd[5], cardcmd[6]};
			data = new byte[lc_extended[1]*256+lc_extended[2]];
			System.arraycopy(cardcmd, 7, data, 0, (lc_extended[1]*256+lc_extended[2]));
			int datalength = lc_extended[1]*256+lc_extended[2];
			le_extended = new byte[] {cardcmd[8+datalength], cardcmd[9+datalength]};
			return CASE4E_CAPDU;
		}
		return 0;
	}

}
