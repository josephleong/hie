import java.io.Serializable;


public class Response implements Serializable {
	public String text;
	
	public Response(String s) {
		this.text = s;
	}
}
