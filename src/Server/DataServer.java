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
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import Requests.CreateEncryptedEHR;
import Requests.EncryptedEHR;
import Requests.IsOwnerCheck;
import Requests.RAReadRecord;
import Requests.RARecordReply;
import Requests.ReadRecord;
import Requests.Reply;
import Requests.Request;
import Requests.UpdateRecord;
import Requests.VerificationRequest;

/**
 * DataServer, handles PHR and HISP requests and authenticates then serves data
 * from Data Store
 * 
 * @author Joseph Leong (leong1), Brett Stevens (steven10)
 * 
 */
public class DataServer implements Runnable {

	private static SSLSocket sslsocket;
	private ObjectOutputStream objOut = null;
	private ObjectInputStream objIn = null;
	
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

	

	/**
	 * Handles the client requests Logs actions to DS.log for auditing
	 * 
	 * @param request
	 *            - client request
	 * @return - a Reply to a client based on the Request and information passed
	 */
	private Reply processRequest(Request request) {
		Reply response = new Reply("Error Processing Request.");
		try {
			if (request instanceof ReadRecord) {
				request = (ReadRecord) request;
				response = getRecord(((ReadRecord) request));
				if(!((ReadRecord) request).getType().equals("hisp"))
				logInfo(((ReadRecord) request).getAgentId()+" READ records");
				else logInfo(((ReadRecord) request).getAgentId()+" READ " +((ReadRecord) request).getRecordId()+"'s records");
			} else if(request instanceof CreateEncryptedEHR) { 
				insertEHR((CreateEncryptedEHR) request);
				response = new Reply("Successfully Created");
				logInfo(((CreateEncryptedEHR) request).getOwner()+" INSRTED " + ((CreateEncryptedEHR) request).getUserId()+"'s record");
			} else if(request instanceof IsOwnerCheck) {
				if(isOwnerCheck((IsOwnerCheck) request)) response = new Reply("true");
				else response = new Reply("false");
			} else if(request instanceof UpdateRecord) {
				response = updateRecord((UpdateRecord)request);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return response;
	}
	
	private Reply updateRecord(UpdateRecord request) {
		Connection connection = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:ds.db");
			String updateString = "update records set ";
			
			if(!request.getName().equals("")) {
				updateString+="name = ?, ";}
			if(!request.getAge().equals("")) {
				updateString+="age = ?, ";}
			if(!request.getWeight().equals("")) {
				updateString+="weight = ?, ";}
			if(!request.getDiagnosis().equals("")) {
				updateString+="diagnosis = ?, ";}
			if(!request.getPrescriptions().equals("")) {
				updateString+="prescriptions = ?, ";}
			if(!request.getOther().equals("")) {
				updateString+="other = ?, ";}
			updateString = updateString.substring(0, updateString.length()-2);
			updateString+= " where userId = '"+request.getUserId()+"';";
					
			//System.out.println(updateString);
			PreparedStatement prep = connection.prepareStatement(updateString);
			int i = 1;
			if(!request.getName().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getName(), request.getKey()));
				i++;
			}
			if(!request.getAge().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getAge(), request.getKey()));
				i++;
			}
			if(!request.getWeight().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getWeight(), request.getKey()));
				i++;
			}	
			if(!request.getDiagnosis().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getDiagnosis(), request.getKey()));
				i++;
			}	
			if(!request.getPrescriptions().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getPrescriptions(), request.getKey()));
				i++;
			}
			if(!request.getOther().equals("")) {
				prep.setBytes(i, Crypto.encrypt(request.getOther(), request.getKey()));
				i++;
			}
			prep.execute();
			return (new Reply("Update Success"));			
			
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
		try {
			connection.close();
		} catch (Exception e) {
			e.printStackTrace();
		}		
		return new Reply("Error Updating");
	}

	private boolean isOwnerCheck(IsOwnerCheck request) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:ds.db");
			statement = connection.createStatement();
			resultSet = statement
					.executeQuery("select owner from records where userId ='"
							+ request.getPatiendId() + "';");
			if (resultSet.next()) {
				if (request.getDoctorId().equals(resultSet.getString("owner"))) {
					return true;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			statement.close();
			connection.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private void insertEHR(CreateEncryptedEHR ehr) {
		Connection conn = null;
		Statement statement = null;
		try {
			Class.forName("org.sqlite.JDBC");
			conn = DriverManager.getConnection("jdbc:sqlite:ds.db");
			statement = conn.createStatement();

			PreparedStatement prep = conn.prepareStatement(
	        "insert into records values (?, ?, ?, ?, ?, ?, ?, ?);");

		    prep.setString(1, ehr.getUserId());
		    prep.setString(2, ehr.getOwner());
		    prep.setBytes(3, ehr.getName());
		    prep.setBytes(4, ehr.getAge());
		    prep.setBytes(5, ehr.getWeight());
		    prep.setBytes(6, ehr.getDiagnosis());
		    prep.setBytes(7, ehr.getPrescriptions());
		    prep.setBytes(8, ehr.getOther());
		    prep.addBatch();
		    		    
		    conn.setAutoCommit(false);
		    prep.executeBatch();
		    conn.setAutoCommit(true);
		} catch (Exception e) {
			e.printStackTrace();
		} try {
			statement.close();
			conn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
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
	private Reply getRecord(ReadRecord rr) {
		Connection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		Reply response = null;
		try {
			Class.forName("org.sqlite.JDBC");
			connection = DriverManager.getConnection("jdbc:sqlite:ds.db");
			statement = connection.createStatement();
			if (rr instanceof RAReadRecord) {
				resultSet = statement.executeQuery("select userId, owner, "
						+ ((RAReadRecord) rr).getColumns()
						+ " from records;");// where "
						//+ ((RAReadRecord) rr).getConditions() + ";");
				ArrayList<EncryptedEHR> list = new ArrayList<EncryptedEHR>();
				while (resultSet.next()) {
					list.add(resultSetToEncEHR(resultSet));

				}
				response = new RARecordReply("", list);
			} else {
				resultSet = statement
					.executeQuery("select * from records where userId = '"
							+ rr.getRecordId() + "';");
								
			if (resultSet.next()) {
				response = resultSetToEncEHR(resultSet);

			} else
				response = new Reply("Invalid Request.");
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
	 * Formats a request into a human-readable string
	 * 
	 * @param resultSet
	 *            - query resultSet
	 * @return a string result
	 */
	private EncryptedEHR resultSetToEncEHR(ResultSet resultSet) {
		try {
			EncryptedEHR ehr = new EncryptedEHR();
			ResultSetMetaData rsmd = resultSet.getMetaData();
			int numColumns = rsmd.getColumnCount();
			String columnName;
			// Get the column names; column indices start from 1
			for (int i = 1; i < numColumns + 1; i++) {
				columnName = rsmd.getColumnName(i);

				if (columnName.equals("userId")) {
					ehr.setUserId(resultSet.getString("userId"));
				} else if (columnName.equals("owner")) {
					ehr.setOwner(resultSet.getString("owner"));
				} else if (columnName.equals("name")) {
					ehr.setName(resultSet.getBytes("name"));
				} else if (columnName.equals("age")) {
					ehr.setAge(resultSet.getBytes("age"));
				} else if (columnName.equals("weight")) {
					ehr.setWeight(resultSet.getBytes("weight"));
				} else if (columnName.equals("diagnosis")) {
					ehr.setDiagnosis(resultSet.getBytes("diagnosis"));
				} else if (columnName.equals("prescriptions")) {
					ehr.setPrescriptions(resultSet.getBytes("prescriptions"));
				} else if (columnName.equals("other")) {
					ehr.setOther(resultSet.getBytes("other"));
				}
			}
			//return new EncryptedEHR(resultSet.getString("userId"), resultSet.getString("owner"), resultSet.getBytes("name"), resultSet.getBytes("age"), resultSet.getBytes("weight"), resultSet.getBytes("diagnosis"), resultSet.getBytes("prescriptions"), resultSet.getBytes("other"));
			return ehr;
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
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
					.createServerSocket(9995);

			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			return sslserversocket;

		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
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
			fh.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
