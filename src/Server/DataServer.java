package Server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.Request;

/**
 * DataServer, handles PHR and HISP requests and authenticates then serves data
 * from Data Store
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 * 
 */
public class DataServer implements Runnable {

	private static SSLSocket sslsocket;

	public static void main(String[] args) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IOException {
		System.out.println("Server Started.");
		SSLServerSocket sslserversocket = handshake();
		while (true) {
			SSLSocket socket = (SSLSocket) sslserversocket.accept();
			new Thread(new DataServer(socket)).start();
		}
	}

	public void run() {
		try {

			OutputStream sslout = sslsocket.getOutputStream();
			ObjectOutputStream objOut = new ObjectOutputStream(sslout);

			InputStream sslIn = sslsocket.getInputStream();
			ObjectInputStream objIn = new ObjectInputStream(sslIn);

			String randNum = Long
					.toString(((long) (Math.random() * Long.MAX_VALUE)));
			objOut.writeObject(new VerificationRequest(Crypto.rsaEncrypt(
					randNum.getBytes(), "authpublic.key")));
			String theirRandNum = (String) objIn.readObject();
			if (!randNum.equals(theirRandNum)) {
				System.out.println("Not Verified");
				return;
			}
			VerificationRequest theirVerificationRequest = (VerificationRequest) objIn
					.readObject();
			objOut.writeObject(new String(Crypto.rsaDecrypt(
					theirVerificationRequest.getEncryptedMessage(),
					"dsprivate.key")));

			Request request = null;
			Reply response = null;
			while ((request = (Request) objIn.readObject()) != null) {
				response = processRequest(request);
				objOut.writeObject(response);
			}
		} catch (EOFException exception) {
			// client just disconnected
		} catch (Exception exception) {
			System.out.println("Exiting Server");
			exception.printStackTrace();
		}
	}

	private DataServer(SSLSocket sock) {
		sslsocket = sock;
	}

	/**
	 * Handles the client requests Logs actions to DS.log for auditing
	 * 
	 * @param request
	 *            - client request
	 * @return - a Reply to a client based on the Request and information passed
	 */
	private static Reply processRequest(Request request)
			throws NoSuchAlgorithmException {
		Reply response = new Reply("Error Processing Request.");
		try {
			FileHandler fh = new FileHandler("DS.log", true);
			fh.setFormatter(new SimpleFormatter());
			Logger logger = Logger.getLogger("DS Log");
			logger.addHandler(fh);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}

	/**
	 * Handles setting up the SSL connection
	 * 
	 * @return - SSLServerSocket for the connection
	 */
	private static SSLServerSocket handshake() {
		try {
			SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory
					.getDefault();

			SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory
					.createServerSocket(9998);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			return sslserversocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}
