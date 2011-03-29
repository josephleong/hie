package Requests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

@SuppressWarnings("serial")
public class CreateRecord extends Request {
	private String patientId;
	private long encryptionKeyId = 0;
	private String information;

	public CreateRecord(String userid, String password) throws IOException {
		super(userid, password);
		InputStream inputstream = System.in;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("What is the patients userId?");
		this.setPatientId(bufferedreader.readLine());
//		System.out.println("Generate encryption keyID! for now... input it");
//		this.setEncryptionKeyId(Long.parseLong(bufferedreader.readLine()));
		System.out.println("Input the health record information!");
		this.setInformation(bufferedreader.readLine());
	}

	public void setEncryptionKeyId(long encryptionKeyId) {
		this.encryptionKeyId = encryptionKeyId;
	}

	public long getEncryptionKeyId() {
		return encryptionKeyId;
	}

	public void setInformation(String information) {
		this.information = information;
	}

	public String getInformation() {
		return information;
	}

	public void setPatientId(String patientId) {
		this.patientId = patientId;
	}

	public String getPatientId() {
		return patientId;
	}

}