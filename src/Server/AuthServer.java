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
import java.util.ArrayList;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import Requests.EncryptedEHR;
import Requests.HISPLogin;
import Requests.PHRLogin;
import Requests.RALogin;
import Requests.RAReadRecord;
import Requests.RARecordReply;
import Requests.ReadRecord;
import Requests.Reply;
import Requests.Request;
import Requests.VerificationRequest;

public class AuthServer implements Runnable {
	private static final String DSIP = "localhost";
	private static final String KSIP = "localhost";
	
	private static SSLSocket sslsocket;
	private ObjectOutputStream DSobjOut = null;
	private ObjectInputStream DSobjIn = null;
	private ObjectOutputStream KSobjOut = null;
	private ObjectInputStream KSobjIn = null;
	private String userId = null;

	private AuthServer(SSLSocket sock) {
		sslsocket = sock;
	}

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		System.out.println("Authentication Server Started.");
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
	
	private void connectToDS(String ip) {
		try {
			SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(ip, 9995);
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
	
	private void connectToKS(String ip) {
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
	private Reply processRequest(Request request)
			throws NoSuchAlgorithmException {
		Reply response = new Reply("Error Processing Request.");
		try {

			if (request instanceof ReadRecord) {
				if(((ReadRecord) request).getType().equals("phr") && ((ReadRecord) request).getRecordId().equals(userId)) {
					response = getRecord((ReadRecord) request);
					logInfo("PHR READ record "+ ((ReadRecord) request).getRecordId());
				} else if(((ReadRecord) request).getType().equals("hisp") && hasReadAccess(((ReadRecord) request).getRecordId())) {
					response = getRecord((ReadRecord) request);
					logInfo("HISP "+((ReadRecord) request).getAgentId() + " READ record "+ ((ReadRecord) request).getRecordId());
				} else if(((ReadRecord) request).getType().equals("ra")) {
					response = getRecord((ReadRecord) request);
					logInfo("RA "+((ReadRecord) request).getAgentId() + " READ records");
				}		
			} else if (request instanceof HISPLogin) {
				if (checkHISPUser(((HISPLogin) request).getUserid(), ((HISPLogin) request)
						.getPassword())) {
					userId = ((HISPLogin) request).getUserid();
					response = new Reply("Welcome!");
				} else response = new Reply("Invalid User Login");
			} else if (request instanceof PHRLogin) {
				if (checkPHRUser(((PHRLogin) request).getUserid(), ((PHRLogin) request).getPassword())) {
					userId = ((PHRLogin) request).getUserid();
					response = new Reply("Welcome!");
				} else response = new Reply("Invalid User Login");
			} else if (request instanceof RALogin) {
				if (checkRAUser(((RALogin) request).getUserid(), ((RALogin) request).getPassword())) {
					userId = ((RALogin) request).getUserid();
					response = new Reply("Welcome!");
				} else response = new Reply("Invalid User Login");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}
	
	/**
	 * Retrieves an EHR 
	 * 
	 * @param userId
	 *            the requested record's associated userId
	 * @return - Server's Reply
	 */
	private Reply getRecord(ReadRecord rr) {
		try {
			if (rr.getType().equals("ra")) {
				DSobjOut.writeObject(getRAPermissions(rr));
				ArrayList<EncryptedEHR> ehrList = (ArrayList<EncryptedEHR>) ((RARecordReply) DSobjIn
						.readObject()).getList();
				byte[] key = null;
				String records = "";
				for(EncryptedEHR ehr: ehrList) {
					KSobjOut.writeObject("get");
					KSobjOut.writeObject(ehr.getUserId());

					key = (byte[]) KSobjIn.readObject();

					records += decryptEHR(ehr, key)+"\n";

				}
				return new Reply(records);
			} else {
				DSobjOut.writeObject(rr);
				Reply rep = (Reply) DSobjIn.readObject();
				if (!rep.getMessage().equals("Error Processing Request.")) {

					EncryptedEHR ehr = (EncryptedEHR) rep;
					KSobjOut.writeObject("get");
					KSobjOut.writeObject(ehr.getUserId());

					byte[] key = (byte[]) KSobjIn.readObject();

					return decryptEHR(ehr, key);

				}

				return rep;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private boolean checkRAUser(String username, String password) throws NoSuchAlgorithmException {
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
					.executeQuery("select password from ra where username = '"
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

	private boolean hasReadAccess(String recordId) {
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
				if (resultSet.getString("agentId").equals(userId))
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
	@SuppressWarnings("unused")
	private boolean isADoctor() {
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

	
	
	private RAReadRecord getRAPermissions(ReadRecord rr) {
		try {
			Class.forName("org.sqlite.JDBC");
			Connection connection = DriverManager.getConnection("jdbc:sqlite:user.db");
			Statement statement = connection.createStatement();
			ResultSet resultSet = statement
					.executeQuery("select columns, conditions from ra where username = '"
							+ rr.getAgentId() + "';");
			if (resultSet.next()) {
				return new RAReadRecord(rr, resultSet.getString("columns"), resultSet.getString("conditions"));
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static Reply decryptEHR(EncryptedEHR ehr, byte[] key) {
		try {
			String message = "UserId: " + ehr.getUserId() + "\n";
			message += "Owner: " + ehr.getOwner() + "\n";
			if (ehr.getName() != null)
				message += "Name: " + Crypto.decrypt(ehr.getName(), key) + "\n";
			if (ehr.getAge() != null)
				message += "Age: " + Crypto.decrypt(ehr.getAge(), key) + "\n";
			if (ehr.getWeight() != null)
				message += "Weight: " + Crypto.decrypt(ehr.getWeight(), key)
						+ "\n";
			if (ehr.getDiagnosis() != null)
				message += "Diagnosis: "
						+ Crypto.decrypt(ehr.getDiagnosis(), key) + "\n";
			if (ehr.getPrescriptions() != null)
				message += "Prescriptions: "
						+ Crypto.decrypt(ehr.getPrescriptions(), key) + "\n";
			if (ehr.getOther() != null)
				message += "Other: " + Crypto.decrypt(ehr.getOther(), key)
						+ "\n";
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
