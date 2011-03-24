import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

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
            
            InputStream sslinput = sslsocket.getInputStream();
            InputStreamReader sslinputreader = new InputStreamReader(sslinput);
            BufferedReader bufferedsslinputreader = new BufferedReader(sslinputreader);

            OutputStream outputstream = sslsocket.getOutputStream();
            OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
            BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

            String string = null, s = null;
            while ((string = bufferedreader.readLine()) != null) {
                bufferedwriter.write(string + '\n');
                bufferedwriter.flush();
                
                s = bufferedsslinputreader.readLine();
                if(s != null) System.out.println(s);
            }
       
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
    
	private static SSLSocket handshake() {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory
					.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(
					"localhost", 9999);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			return sslsocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}