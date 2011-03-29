package Requests;
/**
 * Request to log a PHR user in
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class PHRLogin extends Request {

	public PHRLogin(String userid, String password) {
		super(userid, password);
	}

}
