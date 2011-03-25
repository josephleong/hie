package Requests;

@SuppressWarnings("serial")
public class UpdateRecord extends Request {
	private String patientId;
	private String addInfo;

	public UpdateRecord(String userid, String password, String patientId, String addinfo) {
		super(userid, password);
		this.setPatientId(patientId);
		this.setAddInfo(addinfo);
	}

	public void setPatientId(String patientId) {
		this.patientId = patientId;
	}

	public String getPatientId() {
		return patientId;
	}

	public void setAddInfo(String addInfo) {
		this.addInfo = addInfo;
	}

	public String getAddInfo() {
		return addInfo;
	}

}
