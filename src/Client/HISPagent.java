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
import Requests.ReadRecord;
import Requests.Request;
import Requests.RevokeReadAccess;
import Requests.RevokeWriteAccess;
import Requests.UpdateRecord;
import Server.Reply;

public class HISPagent {
	public static void main(String[] args) {
		try {
			SSLSocket sslsocket = handshake();
            
            InputStream inputstream = System.in;
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

            OutputStream sslOut = sslsocket.getOutputStream();
            ObjectOutputStream objOut = new ObjectOutputStream(sslOut);
                       
            InputStream sslIn = sslsocket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(sslIn);
            
           
            Reply response = null;
            
            System.out.println("Username?");
            String username = bufferedreader.readLine();
            System.out.println("Password?");
            String password = bufferedreader.readLine();

            System.out.println("");
            
            Request request = null;
			while (true) {
				request = createRequest(username, password);
				if (request != null) {
					objOut.writeObject(request);
					response = (Reply) objIn.readObject();
					System.out.println(response.getMessage());
					System.out.println("Press any key to continue.");
					bufferedreader.read();
				}
			}
             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
	private static Request createRequest(String username, String password) throws IOException{
		InputStream inputstream = System.in;
		Request request = null;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("\n" +
				"(1) 'view' an EHR\n" +
				"(2) 'create' EHR\n" +
				"(3) 'grant read' access to an EHR\n" +
				"(4) 'revoke read' access to an EHR\n" +
				"(5) 'grant write' access to an EHR\n" +
				"(6) 'revoke write' access to an EHR\n" +
				"(7) 'add' information to an EHR\n" +
				"(8) 'quit'");
		String command = bufferedreader.readLine();
		if(command.equals("create") || command.equals("1"))
			request = new CreateRecord(username, password);
		else if(command.equals("view") || command.equals("2")) {
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new ReadRecord(username, password, patientId);
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
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			System.out.println("What would you like to add?");
			String info = bufferedreader.readLine();
			request = new UpdateRecord(username, password, patientId, info);
		}
		else if(command.equals("quit") || command.equals("8")) {
			System.out.println("Goodbye.");
			System.exit(1);
		}
		else{
			System.out.print("Invalid command!");
			return null;
		}
			
		return request;
	}
	
	private static SSLSocket handshake() {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket("localhost", 9996);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			return sslsocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}