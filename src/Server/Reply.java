package Server;
import java.io.Serializable;

/**
 * Reply, which includes a String the informs the user of the success of the operation or the information they were trying to get
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 */
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
	
	public boolean equals(Object o) {
		if(o instanceof Reply)
			return ((Reply)o).getMessage().equals(this.getMessage());
		return false;
	}
}
