import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class CreateRecord extends Request {
	String patientId;
	long encryptionKeyId;
	String information;
	
	
	public CreateRecord(String userid, String password) throws IOException {
		super(userid, password);
		InputStream inputstream = System.in;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("What is the patients userId?");
		this.patientId = bufferedreader.readLine();
		System.out.println("Generate encryption keyID! for now... input it");
		this.encryptionKeyId = Long.parseLong(bufferedreader.readLine());
		System.out.println("Input the health record information!");
		this.information = bufferedreader.readLine();
	}

}