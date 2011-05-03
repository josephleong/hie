package Client;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import Requests.CreateRecord;
import Requests.GrantReadAccess;
import Requests.GrantWriteAccess;
import Requests.HISPLogin;
import Requests.ReadRecord;
import Requests.Reply;
import Requests.Request;
import Requests.RevokeReadAccess;
import Requests.RevokeWriteAccess;
import Requests.UpdateRecord;

/**
 * HISP client Agent, Handles all the operations a Hisp agent could make
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class HISPagent {
	private static final String ip = "localhost";
	public static void main(String[] args) {
		try {
			            
            InputStream inputstream = System.in;
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
            
//            System.out.println("Please enter the IP of the server to connect to.");
//            String ip = bufferedreader.readLine();
            SSLSocket sslsocket = handshake(ip);
            
            OutputStream sslOut = sslsocket.getOutputStream();
            ObjectOutputStream objOut = new ObjectOutputStream(sslOut);
                       
            InputStream sslIn = sslsocket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(sslIn);
            
           
            Reply response = null;
            Request request = null;
            String username = "";
            String password = "";
			
            do {
				System.out.println("Username?");
				username = bufferedreader.readLine();
				System.out.println("Password?");
				password = bufferedreader.readLine();
				objOut.writeObject(new HISPLogin(username, password));
				response = (Reply) objIn.readObject();
				System.out.println(response.getMessage());
				System.out.println();
			} while (response.equals(new Reply("Invalid User Login")));
       
            
            while (true) {
				System.out.println("");
				request = createRequest(username, password);
				if (request != null) {
					objOut.writeObject(request);
					response = (Reply) objIn.readObject();
					System.out.println(response.getMessage());
					System.out.println("\nPress ENTER to continue.");
					bufferedreader.read();
				}
			}
             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    /**
     * Creates the HISP creates for a client
     * @param username - The login of the HISP user
     * @param password - The password of the HISP user
     * @return - Returns the request of the operation the user wants to make
     * @throws IOException
     */
	private static Request createRequest(String username, String password) throws IOException{
		InputStream inputstream = System.in;
		Request request = null;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("" +
				"(1) 'view' an EHR\n" +
				"(2) 'create' EHR\n" +
				"(3) 'grant read' access to an EHR\n" +
				"(4) 'revoke read' access to an EHR\n" +
				"(5) 'grant write' access to an EHR\n" +
				"(6) 'revoke write' access to an EHR\n" +
				"(7) 'add' information to an EHR\n" +
				"(8) 'quit'");
		String command = bufferedreader.readLine();
		if(command.equals("view") || command.equals("1")) {
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new ReadRecord(patientId, "hisp", username);
		}
		else if(command.equals("create") || command.equals("2")) {
			System.out.println("What is the patients's userId?");
			String userId = bufferedreader.readLine();
			String owner = username;
			System.out.println("What is the patients's name?");
			String name = bufferedreader.readLine();
			System.out.println("What is the patients's age?");
			String age = bufferedreader.readLine();
			System.out.println("What is the patients's weight?");
			String weight = bufferedreader.readLine();
			System.out.println("What is the patients's diagnosis?");
			String diagnosis = bufferedreader.readLine();
			System.out.println("What are the patients's prescriptions?");
			String prescriptions = bufferedreader.readLine();
			System.out.println("Input any other information.");
			String other = bufferedreader.readLine();
			
			request = new CreateRecord(userId, owner, name, age, weight, diagnosis, prescriptions, other);
		}
		else if(command.equals("grant read") || command.equals("3")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new GrantReadAccess(username, password, agentId, patientId);
		}
		else if(command.equals("revoke read") || command.equals("4")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new RevokeReadAccess(username, password, agentId, patientId);
		}
		else if(command.equals("grant write") || command.equals("5")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new GrantWriteAccess(username, password, agentId, patientId);
		}
		else if(command.equals("revoke write") || command.equals("6")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new RevokeWriteAccess(username, password, agentId, patientId);
		}
		else if(command.equals("add") || command.equals("7")) {
			System.out.println("What is the patients's userId?");
			String userId = bufferedreader.readLine();
			String owner = username;
			System.out.println("What is the patients's name?");
			String name = bufferedreader.readLine();
			System.out.println("What is the patients's age?");
			String age = bufferedreader.readLine();
			System.out.println("What is the patients's weight?");
			String weight = bufferedreader.readLine();
			System.out.println("What is the patients's diagnosis?");
			String diagnosis = bufferedreader.readLine();
			System.out.println("What are the patients's prescriptions?");
			String prescriptions = bufferedreader.readLine();
			System.out.println("Input any other information.");
			String other = bufferedreader.readLine();
			
			request = new UpdateRecord(userId, owner, name, age, weight, diagnosis, prescriptions, other);
		}
		else if(command.equals("quit") || command.equals("8")) {
			System.out.println("Goodbye.");
			System.exit(0);
		}
		else{
			System.out.print("Invalid command!");
			return null;
		}
			
		return request;
	}
	/**
	 * Creates the ssl collection
	 * @param ip - ip of the server
	 * @return
	 */
	private static SSLSocket handshake(String ip) {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(ip, 9996);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			return sslsocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}