package Requests;


/**
 * Request to revoke Read access to a HISP agent, only possible as the owner of the record
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class RevokeReadAccess extends Request {

	private String granteeId;
	private String patientId;
	
	public RevokeReadAccess(String userid, String password, String granteeId, String patientId) {
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
