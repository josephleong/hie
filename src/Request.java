import java.io.Serializable;


public class Request implements Serializable {
	public String text;
	
	public Request(String s) {
		this.text = s;
	}
}
