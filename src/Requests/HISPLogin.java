package Requests;

/**
 * Request to log a HISP user in
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
@SuppressWarnings("serial")
public class HISPLogin extends Request{

	public HISPLogin(String userid, String password) {
		super(userid, password);
	}

}
