package Server;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.CreateRecord;
import Requests.GrantReadAccess;
import Requests.GrantWriteAccess;
import Requests.HISPLogin;
import Requests.PHRLogin;
import Requests.ReadRecord;
import Requests.Request;
import Requests.RevokeReadAccess;
import Requests.RevokeWriteAccess;
import Requests.UpdateRecord;

/**
 * DataServer, handles PHR and HISP requests and authenticates
 * then serves data from Data Store
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class KeyStore implements Runnable {
	
	//AES Key
	private static byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	
	private static SSLSocket sslsocket;
	
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

			Request request = null;
			Reply response = null;
			while ((request = (Request) objIn.readObject()) != null) {
				response = processRequest(request);
				objOut.writeObject(response);
			}
		} catch (EOFException exception) {
			//client just disconnected
		} catch (Exception exception) {
			System.out.println("Exiting Server");
			exception.printStackTrace();
		}
	}
	
	private KeyStore(SSLSocket sock) {
		sslsocket = sock;
	}
	
	/**
	 * Handles the client requests
	 * Logs actions to DS.log for auditing
	 * @param request - client request
	 * @return - a Reply to a client based on the Request and information passed
	 */
	private static Reply processRequest(Request request) throws NoSuchAlgorithmException {
		Reply response = new Reply("Error Processing Request.");
		try {
			FileHandler fh = new FileHandler("DS.log", true);
			fh.setFormatter(new SimpleFormatter());
			Logger logger = Logger.getLogger("DS Log");
			logger.addHandler(fh);
			
			boolean valid = false;
			boolean isDoc = userIsADoctor(request.getUserid());
			if(request instanceof ReadRecord) {
				request = (ReadRecord) request;
				if(((ReadRecord) request).getRecordId() == null){
					valid = checkPHRUser(request.getUserid(), request.getPassword());
					if(valid) {
						response = getRecord(request.getUserid());
						logger.info(request.getUserid() + " READ record " + ((ReadRecord)request).getRecordId());
					}
				}
				else {
					 valid = checkHISPUser(request.getUserid(), request.getPassword());
					if(valid) {
						response = getRecord(((ReadRecord)request).getRecordId(), request.getUserid());
						logger.info(request.getUserid() + " READ record " + ((ReadRecord)request).getRecordId());
					}
				}
			}
			else if(request instanceof CreateRecord) {
				valid = (checkHISPUser(request.getUserid(), request.getPassword()) && userIsADoctor(request.getUserid()));
				if(valid && isDoc) {
					response = createRecord((CreateRecord)request);
					logger.info(request.getUserid() + " CREATE record " + ((CreateRecord)request).getPatientId());
				}
				else if(valid && !isDoc) response = new Reply("Invalid User Login.");
			}
			else if(request instanceof GrantReadAccess) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid && isDoc) {
					response = grantReadAccess((GrantReadAccess)request);
					logger.info(request.getUserid() + " GRANT READ " + ((GrantReadAccess)request).getGranteeId());
				}
				else if(valid && !isDoc) response = new Reply("Invalid User Login.");
			}
			else if(request instanceof RevokeReadAccess) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid && isDoc) {
					response = revokeReadAccess((RevokeReadAccess)request);
					logger.info(request.getUserid() + " REVOKE READ " + ((RevokeReadAccess)request).getGranteeId());
				}
				else if(valid && !isDoc) response = new Reply("Invalid User Login.");
			}
			else if(request instanceof GrantWriteAccess) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid && isDoc) {
					response = grantWriteAccess((GrantWriteAccess)request);
					logger.info(request.getUserid() + " GRANT WRITE " + ((GrantWriteAccess)request).getGranteeId());
				}
				else if(valid && !isDoc) response = new Reply("Invalid User Login.");
			}
			else if(request instanceof RevokeWriteAccess) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid && isDoc) {
					response = revokeWriteAccess((RevokeWriteAccess)request);
					logger.info(request.getUserid() + " REVOKE WRITE " + ((RevokeWriteAccess)request).getGranteeId());
				}
				else if(valid && !isDoc) response = new Reply("Invalid User Login.");
			}
			else if(request instanceof UpdateRecord) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid) {
					response = updateRecord((UpdateRecord)request);
					logger.info(request.getUserid() + " UPDATE record " + ((UpdateRecord)request).getPatientId());
				}
			}
			else if(request instanceof HISPLogin) {
				valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid)
					response = new Reply("Welcome!");
			}
			else if(request instanceof PHRLogin) {
				valid = checkPHRUser(request.getUserid(), request.getPassword());
				if(valid)
					response = new Reply("Welcome!");				
			}
			if(!valid) response = new Reply("Invalid User Login");	
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return response;
	}
	
	/**
	 * Checks to see if a user is a Doctor
	 * @param userId
	 * @return - true if userId corresponds to a doctor, false otherwise
	 */
	private static boolean userIsADoctor(String userId){
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager
					.getConnection("jdbc:sqlite:HISP.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select type from users where username = '" + userId + "';");
	        if(resultSet.next()){
		        if(resultSet.getString("type").equals("doctor"))
		        	check = true;
		        else
		        	check = false;
		        
		     //   resultSet.close();
	        }
	        else
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
	 * Updates an EHR record
	 * @param request
	 * @return - Server's Reply
	 */
	private static Reply updateRecord(UpdateRecord request) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = new Reply("Error");
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + request.getPatientId() + "' and (owner = '"+ request.getUserid() + "' or '" + request.getUserid() + "' in (select agentId from writeAccess where userId = '" + request.getPatientId() + "'));");

	        PreparedStatement prep = null;
	        if(resultSet.next()){
	          	String oldInfo = new String(decrypt(resultSet.getBytes("information")));
	          	statement.close();
	        	String newInfo = oldInfo + "\n" + request.getAddInfo();
	            prep = connection.prepareStatement(
	            "update records set information = ? where userId = ?");

	    	    prep.setBytes(1, encrypt(newInfo));
	    	    prep.setString(2,request.getPatientId());
	    	    prep.executeUpdate();
	    	    response = new Reply("Record succesfully updated!");
	        }           
	        else
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
	 * Checks to see if patientId's record was created by agentId
	 * @param agentId
	 * @param patientId
	 * @return true if agent is the owner, false otherwise
	 */
	private static boolean isOwner(String agentId, String patientId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + patientId + "' and owner = '" + agentId + "';");
			if(resultSet.next()){
	        	return true;
	        }
	        else {
	            return false;
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
		return false;
	}
	
	/**
	 * Revokes read access from non-owner agents
	 * @param request
	 * @return - Server's reply
	 */
	private static Reply revokeReadAccess(RevokeReadAccess request) {
		if (!isOwner(request.getUserid(), request.getPatientId()))
			return new Reply("Invalid Request");
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from readAccess where userId = '" + request.getPatientId() + "' and agentId = '" + request.getGranteeId() + "';");
			if (resultSet.next()) {
				statement.execute("delete from readAccess " +
								"where userId = '" + request.getPatientId() + "' and " +
								"agentId = '" + request.getGranteeId() + "';");

				response = new Reply("Read access succesfully revoked!");
			}
	        else
	        	response = new Reply("Already does not have read access");

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
	 * Grants an agent write access to an EHR
	 * @param request
	 * @return - Server's reply
	 */
	private static Reply grantWriteAccess(GrantWriteAccess request) {
		if (!isOwner(request.getUserid(), request.getPatientId()))
			return new Reply("Invalid Request");
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		PreparedStatement prep = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from writeAccess where userId = '" + request.getPatientId() + "' and agentId = '" + request.getGranteeId() + "';");
			if(resultSet.next()){
	        	response = new Reply("Already has write access");
	        }
	        else
	            prep = connection.prepareStatement(
	            "insert into writeAccess values (?, ?);");

	    	    prep.setString(1, request.getPatientId());
	    	    prep.setString(2, request.getGranteeId());
	    	    prep.addBatch();	    	
	    	    connection.setAutoCommit(false);
	    	    prep.executeBatch();
	    	    connection.setAutoCommit(true);
	    	    response = new Reply("Write access succesfully granted!");

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
	 * Revokes an agent's write access to an EHR
	 * @param request
	 * @return - Server's reply
	 */
	private static Reply revokeWriteAccess(RevokeWriteAccess request) {
		if (!isOwner(request.getUserid(), request.getPatientId()))
			return new Reply("Invalid Request");
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from writeAccess where userId = '" + request.getPatientId() + "' and agentId = '" + request.getGranteeId() + "';");
			if (resultSet.next()) {
				statement.execute("delete from writeAccess " +
								"where userId = '" + request.getPatientId() + "' and " +
								"agentId = '" + request.getGranteeId() + "';");

				response = new Reply("Write access succesfully revoked!");
			}
	        else
	        	response = new Reply("Already does not have write access");

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
	 * Grants an agent read access to an EHR
	 * @param request
	 * @return - Server's reply
	 */
	private static Reply grantReadAccess(GrantReadAccess request) {
		if (!isOwner(request.getUserid(), request.getPatientId()))
			return new Reply("Invalid Request");
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		PreparedStatement prep = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from readAccess where userId = '" + request.getPatientId() + "' and agentId = '" + request.getGranteeId() + "';");
			if(resultSet.next()){
	        	response = new Reply("Already has read access");
	        }
	        else
	            prep = connection.prepareStatement(
	            "insert into readAccess values (?, ?);");

	    	    prep.setString(1, request.getPatientId());
	    	    prep.setString(2, request.getGranteeId());
	    	    prep.addBatch();	    	
	    	    connection.setAutoCommit(false);
	    	    prep.executeBatch();
	    	    connection.setAutoCommit(true);
	    	    response = new Reply("Read access succesfully granted!");

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
	 * Creates an EHR
	 * @param request
	 * @return - Server's Reply
	 */
	private static Reply createRecord(CreateRecord request) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		PreparedStatement prep = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + request.getPatientId() + "';");
			if(resultSet.next()){
	        	response = new Reply("Record already exists, please restart and simply add data to it");
	        }
	        else {
	            prep = connection.prepareStatement(
	            "insert into records values (?, ?, ?, ?);");

	    	    prep.setString(1, request.getPatientId());
	    	    prep.setLong(2, request.getEncryptionKeyId());
	    	    prep.setString(3, request.getUserid());
	    	    prep.setBytes(4, encrypt(request.getInformation()));
	    	    prep.addBatch();	    	
	    	    connection.setAutoCommit(false);
	    	    prep.executeBatch();
	    	    connection.setAutoCommit(true);
	    	    response = new Reply("Record succesfully added!");
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
		return response;
	}
	
	/**
	 * Retrieves an EHR for a patient
	 * @param userId the requested record's associated userId
	 * @return - Server's Reply
	 */
	private static Reply getRecord(String userId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + userId + "';");
	        if(resultSet.next()){
	        	String message = recordToString(resultSet);
	        	response = new Reply(message);
	        }
	        else
	        	response = new Reply("No such record exists.");
		           
	       
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
	 * Retrieves an EHR for an agent
	 * @param userId the requested record's associated userId
	 * @param agent - the requesting agent's Id
	 * @return - Server's Reply
	 */
	private static Reply getRecord(String userId, String agent) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + userId + "' and (owner = '"+ agent + "' or '" + agent + "' in (select agentId from readAccess where userId = '" + userId + "'));");
	        if(resultSet.next()){
	        	String message = recordToString(resultSet);
	        	response = new Reply(message);
	        }
	        else
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
	 * @param resultSet - query resultSet
	 * @return a string result
	 */
	private static String recordToString(ResultSet resultSet) throws SQLException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		String message = "UserId: " + resultSet.getString("userId") + "\n";
		message += "Encryption Key Id: " + resultSet.getLong("encryptionKeyId") + "\n"; 
		message += "Owner: " + resultSet.getString("owner") + "\n"; 
		message += "Information: " + decrypt(resultSet.getBytes("information")) + "\n"; 
		return message;
	}
	
	/**
	 * Authenticates a PHRUser
	 * @param username
	 * @param password
	 * @return - true if authorized, false otherwise
	 */
	private static boolean checkPHRUser(String username, String password) throws NoSuchAlgorithmException{
		MessageDigest m = MessageDigest.getInstance("MD5");
    	m.reset();
    	m.update(password.getBytes());
    	byte[] digest = m.digest();
    	BigInteger bigInt = new BigInteger(1,digest);
    	String hashtext = bigInt.toString(16);
    	
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager
					.getConnection("jdbc:sqlite:PHR.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select password from users where username = '" + username + "';");
	        if(resultSet.next()){
		        if(resultSet.getString("password").equals(hashtext))
		        	check = true;
		        else
		        	check = false;

	        }
	        else
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
	 * @param username
	 * @param password
	 * @return - true if authorized, false otherwise
	 */
	private static boolean checkHISPUser(String username, String password) throws NoSuchAlgorithmException{
		MessageDigest m = MessageDigest.getInstance("MD5");
    	m.reset();
    	m.update(password.getBytes());
    	byte[] digest = m.digest();
    	BigInteger bigInt = new BigInteger(1,digest);
    	String hashtext = bigInt.toString(16);
    	
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		boolean check = false;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager
					.getConnection("jdbc:sqlite:HISP.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select password from users where username = '" + username + "';");
	        if(resultSet.next()){
		        if(resultSet.getString("password").equals(hashtext))
		        	check = true;
		        else
		        	check = false;

	        }
	        else
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
	 * Encrypts a String via AES
	 * @param s - to be encrypted
	 * @return - a byte[] of the encrypted string
	 */
	private static byte[] encrypt(String s) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        
	    byte[] input = s.getBytes();
	    	    
	    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    //IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    Cipher cipher = Cipher.getInstance("AES", "BC");

	    // encryption pass
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    ByteArrayInputStream bIn = new ByteArrayInputStream(input);
	    CipherInputStream cIn = new CipherInputStream(bIn, cipher);
	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

	    int ch;
	    while ((ch = cIn.read()) >= 0) {
	      bOut.write(ch);
	    }

	    byte[] cipherText = bOut.toByteArray();

	    return  (cipherText);
    
	}
	
	/**
	 * Decrypts a String via AES
	 * @param s - to be decrypted
	 * @return - a string of the decrypted byte[]
	 */
	private static String decrypt(byte[] s) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("AES");
		// decryption pass
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    //IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	    CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
	    cOut.write(s);
	    cOut.close();
	    return new String(bOut.toByteArray());
	}

	/**
	 * Handles setting up the SSL connection
	 * @return - SSLServerSocket for the connection
	 */
	private static SSLServerSocket handshake() {
		try {
			SSLServerSocketFactory sslserversocketfactory = 
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			
			SSLServerSocket sslserversocket = 
				(SSLServerSocket) sslserversocketfactory.createServerSocket(9996);
			
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			return sslserversocket;
		
		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
}
