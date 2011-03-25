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
           
            Request request =  createRequest(username, password);
            objOut.writeObject(request);
            response = (Reply)objIn.readObject();
        	System.out.println(response.getMessage());

             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
	private static Request createRequest(String username, String password) throws IOException{
		InputStream inputstream = System.in;
		Request request = null;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("'create' EHR\n'grant read' access to an EHR\n'revoke read' access to an EHR\n'grant write' access to an EHR\n'revoke write' access to an EHR\n'view' an EHR\n'add' information to an EHR");
		String command = bufferedreader.readLine();
		if(command.equals("create"))
			request = new CreateRecord(username, password);
		else if(command.equals("view")) {
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new ReadRecord(username, password, patientId);
		}
		else if(command.equals("grant read")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new GrantReadAccess(username, password, agentId, patientId);
		}
		else if(command.equals("revoke read")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new RevokeReadAccess(username, password, agentId, patientId);
		}
		else if(command.equals("grant write")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new GrantWriteAccess(username, password, agentId, patientId);
		}
		else if(command.equals("revoke write")) {
			System.out.println("What is the agent's userId?");
			String agentId = bufferedreader.readLine();
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			request = new RevokeWriteAccess(username, password, agentId, patientId);
		}
		else if(command.equals("add")) {
			System.out.println("What is the patients userId?");
			String patientId = bufferedreader.readLine();
			System.out.println("What would you like to add?");
			String info = bufferedreader.readLine();
			request = new UpdateRecord(username, password, patientId, info);
		}
		else{
			System.out.print("Invalid command!");
			System.exit(1);
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