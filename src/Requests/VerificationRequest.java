package Requests;


@SuppressWarnings("serial")
public class VerificationRequest extends Request {

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
