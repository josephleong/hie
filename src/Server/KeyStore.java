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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.VerificationRequest;

/**
 * DataServer, handles PHR and HISP requests and authenticates
 * then serves data from Data Store
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class KeyStore implements Runnable {
	
	private static SSLSocket sslsocket;
	
	private KeyStore(SSLSocket sock) {
		sslsocket = sock;
	}
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		System.out.println("Key Store Server Started.");		
		SSLServerSocket sslserversocket = handshake();
		while(true){
			SSLSocket socket = (SSLSocket) sslserversocket.accept();
			new Thread(new KeyStore(socket)).start();
		}
	}
	
	public void run() {
		try {

			OutputStream sslout = sslsocket.getOutputStream();
			ObjectOutputStream objOut = new ObjectOutputStream(sslout);

			InputStream sslIn = sslsocket.getInputStream();
			ObjectInputStream objIn = new ObjectInputStream(sslIn);

			if (!verifyAuthServer(objOut, objIn)) {
				System.out.println("Couldn't Verify");
				return;
			}

			String request = (String) objIn.readObject();
			while (request != null) {
				if (request.equals("get")) {
					String userIdOfRequest = (String) objIn.readObject();
					byte[] key = getKey(userIdOfRequest);
					System.out.println(key);
					logInfo("Retrieving userId " + userIdOfRequest + "'s key.");
					objOut.writeObject(key);

				} else if (request.equals("add")) {
					String userId = (String) objIn.readObject();
					byte[] key = (byte[]) objIn.readObject();
					addKey(userId, key);
					logInfo("Adding userId " + userId + "'s key to KS.");
				}
				request = (String) objIn.readObject();
			}

		} catch (EOFException exception) {
			// client just disconnected
		} catch (Exception exception) {
			System.out.println("Exiting Server");
			exception.printStackTrace();
		}
	}

	private void addKey(String userId, byte[] key) {
		try {
			Class.forName("org.sqlite.JDBC");
			Connection conn = DriverManager.getConnection("jdbc:sqlite:ks.db");
			PreparedStatement prep = conn.prepareStatement(
		        "insert into keys values (?, ?);");

			    prep.setString(1, userId);
			    prep.setBytes(2, key);
			    prep.addBatch();
			    		    
			    conn.setAutoCommit(false);
			    prep.executeBatch();
			    conn.setAutoCommit(true);
			    
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	private byte[] getKey(String userIdOfRequest) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:ks.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select key from keys where userId = '"
							+ userIdOfRequest + "';");
			if (resultSet.next()) {
				return resultSet.getBytes("key");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private boolean verifyAuthServer(ObjectOutputStream objOut,
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
		VerificationRequest theirVerificationRequest = (VerificationRequest) objIn
				.readObject();
		objOut.writeObject(new String(Crypto.rsaDecrypt(
				theirVerificationRequest.getEncryptedMessage(),
				"ksprivate.key")));
		return true;
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
					.createServerSocket(9997);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			return sslserversocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
	
	private static void logInfo(String entry) {
		FileHandler fh;
		try {
			fh = new FileHandler("KS.log", true);
			fh.setFormatter(new SimpleFormatter());
			Logger logger = Logger.getLogger("KS Log");
			logger.addHandler(fh);

			logger.info(entry);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}

