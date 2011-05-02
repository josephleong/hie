package Requests;


/**
 * Request to revoke Write access to a HISP agent, only possible as the owner of the record
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class RevokeWriteAccess extends Request {

	private String granteeId;
	private String patientId;
	
	public RevokeWriteAccess(String userid, String password, String granteeId, String patientId) {
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
