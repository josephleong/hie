package Requests;

/**
 * Request to be made to the Server
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */

@SuppressWarnings("serial")
public class IsOwnerCheck extends Request {
	private String doctorId;
	private String patiendId;
	
	
	public IsOwnerCheck(String doctorId, String patiendId) {
		super();
		this.doctorId = doctorId;
		this.patiendId = patiendId;
	}
	public void setPatiendId(String patiendId) {
		this.patiendId = patiendId;
	}
	public String getPatiendId() {
		return patiendId;
	}
	public void setDoctorId(String doctorId) {
		this.doctorId = doctorId;
	}
	public String getDoctorId() {
		return doctorId;
	}
	
}