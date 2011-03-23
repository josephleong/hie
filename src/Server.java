import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Server {
	public static void main(String[] args) {
		try {
			SSLSocket sslsocket = handshake();
			
			InputStream inputstream = sslsocket.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
			
			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				System.out.println(string);
				System.out.flush();
			}
		
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static SSLSocket handshake() {
		try {
			SSLServerSocketFactory sslserversocketfactory = 
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			
			SSLServerSocket sslserversocket = 
				(SSLServerSocket) sslserversocketfactory.createServerSocket(9999);
			
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();

			return sslsocket;
		
		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}

