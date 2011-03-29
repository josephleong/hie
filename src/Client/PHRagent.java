package Client;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import Requests.PHRLogin;
import Requests.ReadRecord;
import Server.Reply;

public
class PHRagent {
	public static void main(String[] args) {
		try {
			       
            InputStream inputstream = System.in;
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

            System.out.println("Please enter the IP of the server to connect to.");
            String ip = bufferedreader.readLine();
            SSLSocket sslsocket = handshake(ip);
            
            OutputStream sslOut = sslsocket.getOutputStream();
            ObjectOutputStream objOut = new ObjectOutputStream(sslOut);
                       
            InputStream sslIn = sslsocket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(sslIn);
            
           
            Reply response = null;
            String username = "";
            String password = "";
            do {
				System.out.println("Username?");
				username = bufferedreader.readLine();
				System.out.println("Password?");
				password = bufferedreader.readLine();
				objOut.writeObject(new PHRLogin(username, password));
				response = (Reply) objIn.readObject();
				System.out.println(response.getMessage());
				System.out.println();
			} while (response.equals(new Reply("Invalid User Login")));
                       
            ReadRecord request= new ReadRecord(username, password);	
            objOut.writeObject(request);
            response = (Reply)objIn.readObject();
        	System.out.println(response.getMessage());

             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
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