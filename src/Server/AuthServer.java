package Server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import Requests.HISPLogin;
import Requests.PHRLogin;
import Requests.ReadRecord;
import Requests.Request;

public class AuthServer implements Runnable {
	private static final String DSIP = "localhost";
	private static final String KSIP = "localhost";
	
	private static SSLSocket sslsocket;
	private static ObjectOutputStream DSobjOut = null;
	private static ObjectInputStream DSobjIn = null;
	private static ObjectOutputStream KSobjOut = null;
	private static ObjectInputStream KSobjIn = null;

	private AuthServer(SSLSocket sock) {
		sslsocket = sock;
	}

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		System.out.println("Server Started.");
		SSLServerSocket sslserversocket = handshake();
		while (true) {
			SSLSocket socket = (SSLSocket) sslserversocket.accept();
			new Thread(new AuthServer(socket)).start();
		}
	}

	public void run() {
		try {

			OutputStream sslout = sslsocket.getOutputStream();
			ObjectOutputStream objOut = new ObjectOutputStream(sslout);
			InputStream sslIn = sslsocket.getInputStream();
			ObjectInputStream objIn = new ObjectInputStream(sslIn);
			connectToDS(DSIP);
			connectToKS(KSIP);
			
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
	
	private static void connectToDS(String ip) {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(ip, 9998);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			
			OutputStream sslout = sslsocket.getOutputStream();
			DSobjOut = new ObjectOutputStream(sslout);

			InputStream sslIn = sslsocket.getInputStream();
			DSobjIn = new ObjectInputStream(sslIn);
			
			VerificationRequest theirVerificationRequest = (VerificationRequest) DSobjIn.readObject();
			DSobjOut.writeObject(new String(Crypto.rsaDecrypt(theirVerificationRequest.getEncryptedMessage(), "authprivate.key")));
			String randNum = Long.toString(((long)(Math.random()*Long.MAX_VALUE)));
			DSobjOut.writeObject(new VerificationRequest(Crypto.rsaEncrypt(randNum.getBytes(), "dspublic.key")));
			String theirRandNum = (String) DSobjIn.readObject();
			
			if(!randNum.equals(theirRandNum)) {
				System.out.println("Not Verified");
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static void connectToKS(String ip) {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(ip, 9997);
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslsocket.setEnabledCipherSuites(enabledCipherSuites);
			
			OutputStream sslout = sslsocket.getOutputStream();
			KSobjOut = new ObjectOutputStream(sslout);

			InputStream sslIn = sslsocket.getInputStream();
			KSobjIn = new ObjectInputStream(sslIn);
			
			VerificationRequest theirVerificationRequest = (VerificationRequest) KSobjIn.readObject();
			KSobjOut.writeObject(new String(Crypto.rsaDecrypt(theirVerificationRequest.getEncryptedMessage(), "authprivate.key")));
			String randNum = Long.toString(((long)(Math.random()*Long.MAX_VALUE)));
			KSobjOut.writeObject(new VerificationRequest(Crypto.rsaEncrypt(randNum.getBytes(), "kspublic.key")));
			String theirRandNum = (String) KSobjIn.readObject();
			if(!randNum.equals(theirRandNum)) {
				System.out.println("Not Verified");
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
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
					.createServerSocket(9996);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			return sslserversocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}

	/**
	 * Handles the client requests Logs actions to AuthServer.log for auditing
	 * 
	 * @param request
	 *            - client request
	 * @return - a Reply to a client based on the Request and information passed
	 */
	private static Reply processRequest(Request request)
			throws NoSuchAlgorithmException {
		Reply response = new Reply("Error Processing Request.");
		try {
			boolean valid = false;
			//boolean isDoc = userIsADoctor(request.getUserid());
			if (request instanceof ReadRecord) {
				request = (ReadRecord) request;
				if (((ReadRecord) request).getRecordId() == null) {
					valid = checkPHRUser(request.getUserid(), request.getPassword());
					if (valid) {
						response = getRecord(request.getUserid());
						logInfo(request.getUserid() + " READ record "+ ((ReadRecord) request).getUserid());
					}
				} else {
					valid = checkHISPUser(request.getUserid(), request.getPassword());
					valid = valid && hasReadAccess(request.getUserid(), ((ReadRecord) request).getRecordId());
					if (valid) {
						response = getRecord(((ReadRecord) request).getRecordId());
						logInfo(request.getUserid() + " READ record "
								+ ((ReadRecord) request).getRecordId());
					}
				}
			} else if (request instanceof HISPLogin) {
				valid = checkHISPUser(request.getUserid(), request
						.getPassword());
				if (valid)
					response = new Reply("Welcome!");
			} else if (request instanceof PHRLogin) {
				valid = checkPHRUser(request.getUserid(), request.getPassword());
				if (valid)
					response = new Reply("Welcome!");
			}
			if (!valid)
				response = new Reply("Invalid User Login");

		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}

	private static boolean hasReadAccess(String userid, String recordId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:user.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select agentId from readAccess where userId = '"
							+ recordId + "';");

			while (resultSet.next()) {
				if (resultSet.getString("agentId").equals(userid))
					check = true;
			}

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
		return check;

	}

	/**
	 * Checks to see if a user is a Doctor
	 * 
	 * @param userId
	 * @return - true if userId corresponds to a doctor, false otherwise
	 */
	private static boolean userIsADoctor(String userId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:user.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select type from hisp where username = '"
							+ userId + "';");
			if (resultSet.next()) {
				if (resultSet.getString("type").equals("doctor"))
					check = true;
				else
					check = false;

				// resultSet.close();
			} else
				check = false;

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
		return check;
	}



	/**
	 * Retrieves an EHR 
	 * 
	 * @param userId
	 *            the requested record's associated userId
	 * @return - Server's Reply
	 */
	private static Reply getRecord(String userId) {
		try {

			DSobjOut.writeObject(new ReadRecord(userId));

			Reply rep = (Reply) DSobjIn.readObject();
			if (!rep.getMessage().equals("Error Processing Request.")) {
				EncryptedEHR ehr = (EncryptedEHR) rep;
				KSobjOut.writeObject("get");
				KSobjOut.writeObject(ehr.getUserId());

				byte[] key = (byte[]) KSobjIn.readObject();

				return decryptEHR(ehr, key);
			}
			return rep;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static Reply decryptEHR(EncryptedEHR ehr, byte[] key) {
		try {
			System.out.println(Crypto.decrypt(ehr.getName(), key));
		String message = "UserId: " + ehr.getUserId() + "\n";
		message += "Owner: " + ehr.getOwner() + "\n";
		message += "Name: " + Crypto.decrypt(ehr.getName(), key)+ "\n";
		message += "Age: " + Crypto.decrypt(ehr.getAge(), key)+ "\n";
		message += "Weight: " + Crypto.decrypt(ehr.getWeight(), key)+ "\n";
		message += "Diagnosis: " + Crypto.decrypt(ehr.getDiagnosis(), key)+ "\n";
		message += "Prescriptions: " + Crypto.decrypt(ehr.getPrescriptions(), key)+ "\n";
		message += "Other: " + Crypto.decrypt(ehr.getOther(), key)+ "\n";
		return new Reply(message);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Authenticates a PHRUser
	 * 
	 * @param username
	 * @param password
	 * @return - true if authorized, false otherwise
	 */
	private static boolean checkPHRUser(String username, String password)
			throws NoSuchAlgorithmException {
		MessageDigest m = MessageDigest.getInstance("MD5");
		m.reset();
		m.update(password.getBytes());
		byte[] digest = m.digest();
		BigInteger bigInt = new BigInteger(1, digest);
		String hashtext = bigInt.toString(16);

		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:user.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select password from phr where username = '"
							+ username + "';");
			if (resultSet.next()) {
				if (resultSet.getString("password").equals(hashtext))
					check = true;
				else
					check = false;

			} else
				check = false;

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
		return check;
	}

	/**
	 * Authenticates a HISPUser
	 * 
	 * @param username
	 * @param password
	 * @return - true if authorized, false otherwise
	 */
	private static boolean checkHISPUser(String username, String password)
			throws NoSuchAlgorithmException {
		MessageDigest m = MessageDigest.getInstance("MD5");
		m.reset();
		m.update(password.getBytes());
		byte[] digest = m.digest();
		BigInteger bigInt = new BigInteger(1, digest);
		String hashtext = bigInt.toString(16);

		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:user.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select password from hisp where username = '"
							+ username + "';");
			if (resultSet.next()) {
				if (resultSet.getString("password").equals(hashtext))
					check = true;
				else
					check = false;

			} else
				check = false;

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
		return check;
	}

	private static void logInfo(String entry) {
		FileHandler fh;
		try {
			fh = new FileHandler("AuthServer.log", true);
			fh.setFormatter(new SimpleFormatter());
			Logger logger = Logger.getLogger("Auth Server Log");
			logger.addHandler(fh);

			logger.info(entry);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
