package Requests;

/**
 * The request to read a EHR record from either a HISP user or the PHR patient
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class ReadRecord extends Request {
	private String recordId;

	public ReadRecord(String recordId) {
		super("userid", "password");
		this.recordId = recordId;
	}
	public ReadRecord(String userid, String password) {
		super(userid, password);
	}

	public ReadRecord(String userid, String password, String recordId) {
		super(userid, password);
		this.setRecordId(recordId);
	}

	public void setRecordId(String recordId) {
		this.recordId = recordId;
	}

	public String getRecordId() {
		return recordId;
	}

}