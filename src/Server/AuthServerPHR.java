package Server;
import java.io.BufferedReader;


import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;


public class AuthServerPHR {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {

		try {
			SSLServerSocketFactory sslserversocketfactory = 
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

			SSLServerSocket sslserversocket = 
				(SSLServerSocket) sslserversocketfactory.createServerSocket(9997);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);
			
			SSLSocket sslsocket = null;
			while((sslsocket = (SSLSocket) sslserversocket.accept()) != null){
	
				InputStream inputstream = sslsocket.getInputStream();
				InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
				BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
	
				OutputStream outputstream = sslsocket.getOutputStream();
	            OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
	            BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
	
	            String username = null;
	            String password = null;
	            boolean verification = false;
		        username = bufferedreader.readLine();
		        password = bufferedreader.readLine();
	            verification = checkPassword(password, username); 
				bufferedwriter.write(verification + "\n");
				bufferedwriter.flush();
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}

	
	private static boolean checkPassword(String plainText, String name) throws NoSuchAlgorithmException{

		
    	MessageDigest m = MessageDigest.getInstance("MD5");
    	m.reset();
    	m.update(plainText.getBytes());
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
	        resultSet = statement.executeQuery("select password from users where username = '" + name + "';");
	        if(resultSet.getString("password").equals(hashtext))
	        	check = true;
	        else
	        	check = false;
	           
	       
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				resultSet.close();
				statement.close();
				connection.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return check;
	}
	
	
}
