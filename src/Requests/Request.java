package Requests;
import java.io.Serializable;

@SuppressWarnings("serial")
public class Request implements Serializable {
	private String userid;
	private String password;

	public Request(String userid, String password) {
		this.setUserid(userid);
		this.setPassword(password);
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