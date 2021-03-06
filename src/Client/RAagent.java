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

import Requests.RALogin;
import Requests.ReadRecord;
import Requests.Reply;
import Requests.VerificationRequest;
import Server.Crypto;

/**
 * PHR agent, Handles all the operations a PHR agent could make
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class RAagent {
	private static String ip = "localhost"; // IP of AuthServer
	
	public static void main(String[] args) {
	try {
			if (args.length != 0)
				ip = args[0];

            InputStream inputstream = System.in;
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

            SSLSocket sslsocket = handshake(ip);
            
            OutputStream sslOut = sslsocket.getOutputStream();
            ObjectOutputStream objOut = new ObjectOutputStream(sslOut);
                       
            InputStream sslIn = sslsocket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(sslIn);
            if(!verifyAuthServer(objOut, objIn)) { System.out.println("Couldn't Verify"); return; }
           
            Reply response = null;
            String username = "";
            String password = "";
            do {
				System.out.println("Username?");
				username = bufferedreader.readLine();
				System.out.println("Password?");
				password = bufferedreader.readLine();
				
				objOut.writeObject(new RALogin(username, password));
				response = (Reply) objIn.readObject();
				System.out.println(response.getMessage());
				System.out.println();
			} while (response.equals(new Reply("Invalid User Login")));
                       
            ReadRecord request= new ReadRecord(null, "ra", username);	
            long startTime = System.currentTimeMillis();
            objOut.writeObject(request);
            response = (Reply)objIn.readObject();
            long endTime = System.currentTimeMillis();
        	System.out.println(response.getMessage());
        	System.out.println("Time: "+ (endTime - startTime) + " ms");

             
        } catch (Exception exception) {
            exception.printStackTrace();
        }
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
	
	private static boolean verifyAuthServer(ObjectOutputStream objOut,
			ObjectInputStream objIn) throws IOException, ClassNotFoundException {
		String randNum = Long
				.toString(((long) (Math.random() * Long.MAX_VALUE)));
		objOut.writeObject(new VerificationRequest(Crypto.rsaEncrypt(
				randNum.getBytes(), "authpublic.key")));
		String theirRandNum = (String) objIn.readObject();
		if (!randNum.equals(theirRandNum)) {
			System.out.println("Not Verified");
			return false;
		}
		return true;
	}
}