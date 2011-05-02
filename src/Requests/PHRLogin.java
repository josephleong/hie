package Requests;
/**
 * Request to log a PHR user in
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class PHRLogin extends Request {

	private String userid;
	private String password;

	public PHRLogin(String userid, String password) {
		super();
		this.userid = userid;
		this.password = password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPassword() {
		return password;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public String getUserid() {
		return userid;
	}

}
