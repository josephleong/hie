import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public
class HISPagent {
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
            
           
            Response response = null;
            
            System.out.println("Username?");
            String username = bufferedreader.readLine();
            System.out.println("Password?");
            String password = bufferedreader.readLine();
           
            Request request =  createRequest(username, password);
            objOut.writeObject(request);
            response = (Response)objIn.readObject();
        	System.out.println(response.message);

             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
	private static Request createRequest(String username, String password) throws IOException{
		InputStream inputstream = System.in;
		Request request = null;
		InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
		BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
		System.out.println("'create' EHR\n'grant' access to an EHR\n'revoke' access to an EHR\n'view' an EHR\n'add' information to an EHR");
		String command = bufferedreader.readLine();
		if(command.equals("create"))
			request = new CreateRecord(username, password);
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