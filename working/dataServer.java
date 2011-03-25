import java.io.BufferedReader;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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
import java.sql.PreparedStatement;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

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
	            Response response = null;
	            request = (Request)objIn.readObject();
            	response = processRequest(request);
            	objOut.writeObject(response);
	        
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static Response processRequest(Request request) throws NoSuchAlgorithmException {
		Response response = null;
		if(request instanceof ReadRecord) {
			request = (ReadRecord) request;
			if(((ReadRecord) request).recordId == null){
				boolean valid = checkPHRUser(request.userid, request.password);
				if(valid)
					response = getRecord(request.userid);
				else
					response = new Response("Invalid User Login");
			}
		}
		else if(request instanceof CreateRecord){
			boolean valid = checkHISPUser(request.userid, request.password);
			if(valid)
				response = createRecord((CreateRecord)request);
		}
			
		return response;
	}
	
	
	private static Response createRecord(CreateRecord request) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Response response = null;
		PreparedStatement prep = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + request.patientId + "';");
			if(resultSet.next()){
	        	response = new Response("Record already exists, please restart and simply add data to it");
	        }
	        else
	            prep = connection.prepareStatement(
	            "insert into records values (?, ?, ?, ?);");

	    	    prep.setString(1, request.patientId);
	    	    prep.setLong(2, request.encryptionKeyId);
	    	    prep.setString(3, request.userid);
	    	    prep.setBytes(4, encrypt(request.information));
	    	    prep.addBatch();	    	
	    	    connection.setAutoCommit(false);
	    	    prep.executeBatch();
	    	    connection.setAutoCommit(true);
	    	    response = new Response("Record succesfully added!");
		           
	       
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

	private static Response getRecord(String userId) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Response response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:DS.db");
			statement = connection.createStatement();
	        resultSet = statement.executeQuery("select * from records where userId = '" + userId + "';");
	        if(resultSet.next()){
	        	String message = recordToString(resultSet);
	        	response = new Response(message);
	        }
	        else
	        	response = new Response("No such record exists.");
		           
	       
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

