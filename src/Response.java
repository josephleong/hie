import java.io.Serializable;


@SuppressWarnings("serial")
public class Response implements Serializable {
	String message;

	
	public Response(String message){
		this.message = message;
	}
}
