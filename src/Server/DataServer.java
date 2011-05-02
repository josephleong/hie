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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.ReadRecord;
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
	private static ObjectOutputStream objOut = null;
	private static ObjectInputStream objIn = null;
	
	private DataServer(SSLSocket sock) {
		sslsocket = sock;
	}
	
	public static void main(String[] args) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IOException {
		System.out.println("Data Store Server Started.");
		SSLServerSocket sslserversocket = handshake();
		while (true) {
			SSLSocket socket = (SSLSocket) sslserversocket.accept();
			new Thread(new DataServer(socket)).start();
		}
	}

	public void run() {
		try {

			OutputStream sslout = sslsocket.getOutputStream();
			objOut = new ObjectOutputStream(sslout);

			InputStream sslIn = sslsocket.getInputStream();
			objIn = new ObjectInputStream(sslIn);

			if(!verifyAuthServer(objOut, objIn)) { System.out.println("Couldn't Verify"); return; }

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
				"dsprivate.key")));
		return true;
	}

	private static void logInfo(String entry) {
		FileHandler fh;
		try {
			fh = new FileHandler("DS.log", true);
			fh.setFormatter(new SimpleFormatter());
			Logger logger = Logger.getLogger("DS Log");
			logger.addHandler(fh);

			logger.info(entry);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Handles the client requests Logs actions to DS.log for auditing
	 * 
	 * @param request
	 *            - client request
	 * @return - a Reply to a client based on the Request and information passed
	 */
	private static Reply processRequest(Request request) {
		Reply response = new Reply("Error Processing Request.");
		try {
			if (request instanceof ReadRecord) {
				request = (ReadRecord) request;

				response = getRecord(((ReadRecord) request).getRecordId());
				logInfo("READ record "
						+ ((ReadRecord) request).getRecordId());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}
	
	/**
	 * Retrieves an EHR for an agent
	 * 
	 * @param userId
	 *            the requested record's associated userId
	 * @param agent
	 *            - the requesting agent's Id
	 * @return - Server's Reply
	 */
	private static Reply getRecord(String userId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:ds.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select * from records where userId = '"
							+ userId + "';");
			if (resultSet.next()) {
				response = recordToReply(resultSet);

			} else
				response = new Reply("Invalid Request.");

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				statement.close();
				connection.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return response;
	}
	
	/**
	 * Formats a request into a human-readable string
	 * 
	 * @param resultSet
	 *            - query resultSet
	 * @return a string result
	 */
	private static Reply recordToReply(ResultSet resultSet) {
		try {
			return new EncryptedEHR(resultSet.getString("userId"), resultSet.getString("owner"), resultSet.getBytes("name"), resultSet.getBytes("age"), resultSet.getBytes("weight"), resultSet.getBytes("diagnosis"), resultSet.getBytes("prescriptions"), resultSet.getBytes("other"));
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return new Reply("Error Fetching Record");
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
