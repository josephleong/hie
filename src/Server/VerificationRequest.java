package Server;

import java.io.Serializable;

@SuppressWarnings("serial")
public class VerificationRequest implements Serializable {

	private byte[] encryptedMessage;

	public byte[] getEncryptedMessage() {
		return encryptedMessage;
	}

	public void setEncryptedMessage(byte[] encryptedMessage) {
		this.encryptedMessage = encryptedMessage;
	}

	public VerificationRequest(byte[] encryptedMessage) {
		this.encryptedMessage = encryptedMessage;

	}
}
