import java.io.Serializable;


public class Request implements Serializable {
	String userid;
	String password;

	public Request(String userid, String password) {
		this.userid = userid;
		this.password = password;
	}
}