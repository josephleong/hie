package Requests;
import java.util.ArrayList;

/**
 * Reply, which includes a String the informs the user of the success of the operation or the information they were trying to get
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class RARecordReply extends Reply {
	private ArrayList<EncryptedEHR> list;

	public RARecordReply(String message, ArrayList<EncryptedEHR> list) {
		super(message);
		this.list = list;
	}

	public ArrayList<EncryptedEHR> getList() {
		return list;
	}

	public void setList(ArrayList<EncryptedEHR> list) {
		this.list = list;
	}
}
