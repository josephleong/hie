package Server;
import java.io.Serializable;


@SuppressWarnings("serial")
public class Reply implements Serializable {
	private String message;

	
	public Reply(String message){
		this.setMessage(message);
	}


	public void setMessage(String message) {
		this.message = message;
	}


	public String getMessage() {
		return message;
	}
	
	public String toString() {
		return message;
	}
}
