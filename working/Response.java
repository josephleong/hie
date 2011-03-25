import java.io.Serializable;


public class Response implements Serializable {
	String message;

	
	public Response(String message){
		this.message = message;
	}
}
