package Requests;

@SuppressWarnings("serial")
public class GrantReadAccess extends Request {
	private String granteeId;
	private String patientId;
	
	public GrantReadAccess(String userid, String password, String granteeId, String patientId) {
		super(userid, password);
		this.setGranteeId(granteeId);
		this.setPatientId(patientId);
	}

	public void setGranteeId(String granteeId) {
		this.granteeId = granteeId;
	}

	public String getGranteeId() {
		return granteeId;
	}

	public void setPatientId(String patientId) {
		this.patientId = patientId;
	}

	public String getPatientId() {
		return patientId;
	}

}
