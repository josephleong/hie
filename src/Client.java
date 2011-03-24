import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.sql.Date;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public
class Client {
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
            
            String string = null;
            Response response = null;
            Request request = null;
            while ((string = bufferedreader.readLine()) != null) {
            	request = new Request(11111111111L);
            	objOut.writeObject(request);
                response = (Response)objIn.readObject();
                
            }
       
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
	private static SSLSocket handshake() {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket("localhost", 9999);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			return sslsocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}