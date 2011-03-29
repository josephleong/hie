package Requests;
/**
 * The request to Grant Read Access from a HISP user with write access to another
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class GrantWriteAccess extends Request {

	private String granteeId;
	private String patientId;
	
	public GrantWriteAccess(String userid, String password, String granteeId, String patientId) {
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
