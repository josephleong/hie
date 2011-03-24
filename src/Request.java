import java.io.Serializable;
import java.sql.Date;


public class Request implements Serializable {
	long uid;
	
	public Request(long uid) {
		this.uid = uid;
		System.out.println("Request");
	}
}
