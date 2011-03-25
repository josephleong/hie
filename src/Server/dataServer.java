package Server;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.CreateRecord;
import Requests.GrantReadAccess;
import Requests.GrantWriteAccess;
import Requests.ReadRecord;
import Requests.Request;
import Requests.RevokeReadAccess;
import Requests.RevokeWriteAccess;
import Requests.UpdateRecord;

public class dataServer {
	
	private static byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	private static byte[] ivBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x00, 0x01 };
	
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
				
		try {
			SSLServerSocketFactory sslserversocketfactory = 
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

			SSLServerSocket sslserversocket = 
				(SSLServerSocket) sslserversocketfactory.createServerSocket(9996);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);
			
			SSLSocket sslsocket = null;
			while((sslsocket = (SSLSocket) sslserversocket.accept()) != null){
	
			
				OutputStream sslout = sslsocket.getOutputStream();
				ObjectOutputStream objOut = new ObjectOutputStream(sslout);
				
				InputStream sslIn = sslsocket.getInputStream();
				ObjectInputStream objIn = new ObjectInputStream(sslIn);
		
	            Request request = null;
	            Reply response = null;
	            request = (Request)objIn.readObject();
            	response = processRequest(request);
            	objOut.writeObject(response);
	        
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static Reply processRequest(Request request) throws NoSuchAlgorithmException {
		Reply response = null;
		if(request instanceof ReadRecord) {
			request = (ReadRecord) request;
			if(((ReadRecord) request).getRecordId() == null){
				boolean valid = checkPHRUser(request.getUserid(), request.getPassword());
				if(valid)
					response = getRecord(request.getUserid());
				else
					response = new Reply("Invalid User Login");
			}
			else {
				boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
				if(valid)
					response = getRecord(((ReadRecord)request).getRecordId(), request.getUserid());
				else
					response = new Reply("Invalid User Login");
			}
		}
		else if(request instanceof CreateRecord) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = createRecord((CreateRecord)request);
			else
				response = new Reply("Invalid User Login");
		}
		else if(request instanceof GrantReadAccess) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = grantReadAccess((GrantReadAccess)request);
			else
				response = new Reply("Invalid User Login");
		}
		else if(request instanceof RevokeReadAccess) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = revokeReadAccess((RevokeReadAccess)request);
			else
				response = new Reply("Invalid User Login");
		}
		else if(request instanceof GrantWriteAccess) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = grantWriteAccess((GrantWriteAccess)request);
			else
				response = new Reply("Invalid User Login");
		}
		else if(request instanceof RevokeWriteAccess) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = revokeWriteAccess((RevokeWriteAccess)request);
			else
				response = new Reply("Invalid User Login");
		}
		else if(request instanceof UpdateRecord) {
			boolean valid = checkHISPUser(request.getUserid(), request.getPassword());
			if(valid)
				response = updateRecord((UpdateRecord)request);
			else
				response = new Reply("Invalid User Login");
		}
			
		return response;
	}
	
	private static Reply updateRecord(UpdateRecord request) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + request.getPatientId() + "' and (owner = '"+ request.getUserid() + "' or '" + request.getUserid() + "' in (select agentId from writeAccess where userId = '" + request.getPatientId() + "'));");
	        if(resultSet.next()){
	        	//TODO: FIX!!!
	        	String oldInfo = new String(decrypt(resultSet.getBytes("information")));
	        	statement.executeUpdate("update records set information = '" + new String(encrypt(oldInfo + request.getAddInfo())) + "' where userId = '" + request.getPatientId() + "';");
	        	response = new Reply("Update Successful");
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
	        else
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

	private static String recordToString(ResultSet resultSet) throws SQLException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		String message = "UserId: " + resultSet.getString("userId") + "\n";
		message += "Encryption Key Id: " + resultSet.getLong("encryptionKeyId") + "\n"; 
		message += "Owner: " + resultSet.getString("owner") + "\n"; 
		message += "Information: " + decrypt(resultSet.getBytes("information")) + "\n"; 
		return message;
	}
	
	private static byte[] encrypt(String s) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        
	    byte[] input = s.getBytes();
	    
	    
	    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

	    // encryption pass
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
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
	
	private static String decrypt(byte[] s) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		// decryption pass
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	    CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
	    cOut.write(s);
	    cOut.close();
	    return new String(bOut.toByteArray());
	}
}

