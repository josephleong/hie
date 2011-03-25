package Requests;

@SuppressWarnings("serial")
public class ReadRecord extends Request {
	private String recordId;

	public ReadRecord(String userid, String password) {
		super(userid, password);
		// TODO Auto-generated constructor stub
	}

	public ReadRecord(String userid, String password, String recordId) {
		super(userid, password);
		this.setRecordId(recordId);
		// TODO Auto-generated constructor stub
	}

	public void setRecordId(String recordId) {
		this.recordId = recordId;
	}

	public String getRecordId() {
		return recordId;
	}

}