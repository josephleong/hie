public class ReadRecord extends Request {
	String recordId;
	public ReadRecord(String userid, String password) {
		super(userid, password);
		// TODO Auto-generated constructor stub
	}
	public ReadRecord(String userid, String password, String recordId) {
		super(userid, password);
		this.recordId = recordId;
		// TODO Auto-generated constructor stub
	}

}