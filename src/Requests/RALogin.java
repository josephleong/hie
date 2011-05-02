package Requests;

/**
 * Request to log a RA user in
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class RALogin extends Request{

	private String userid;
	private String password;

	public RALogin(String userid, String password) {
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
