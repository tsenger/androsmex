package de.tsenger.androsmex;

public class ResponseAPDU {
	
	private byte[] data = null;
	private byte[] sw = null;
	private byte[] cardresponse = null;
	
	
	public ResponseAPDU(byte[] response) {
		cardresponse = response;
		int rsplength = cardresponse.length;
		if (rsplength==2){
			sw = cardresponse;
		}
		else {
			sw = new byte[] {cardresponse[rsplength-2], cardresponse[rsplength-1]};
			data = new byte[rsplength-2];
			for (int i = 0;i<rsplength-2;i++) {
				data[i] = cardresponse[i];
			}
		}
	}
	
	public byte[] sw() {
		return sw;
	}
	
	public byte[] data() {
		return data;
	}
	
	public byte sw1() {
		return sw[0];
	}
	
	public byte sw2() {
		return sw[1];
	}
	
	public byte[] getBytes() {
		return cardresponse;
	}
}
