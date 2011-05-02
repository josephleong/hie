package DB;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
/**
 * Creates a sample Data Store databse with a sample record
 *  @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class StoreDB {

    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:ds.db");
        Statement stat = conn.createStatement();
        stat.executeUpdate("drop table if exists records;");
        stat.executeUpdate("create table records (userId, owner, name, age, weight, diagnosis, prescriptions, other);");
               
        byte[] key1 = generateAESKey();
        byte[] key2 = generateAESKey();
                
        PreparedStatement prep = conn.prepareStatement(
        "insert into records values (?, ?, ?, ?, ?, ?, ?, ?);");

	    prep.setString(1, "1");
	    prep.setString(2, "Doctor1");
	    prep.setBytes(3, encrypt("Patient1", key1));
	    prep.setBytes(4, encrypt("25", key1));
	    prep.setBytes(5, encrypt("160", key1));
	    prep.setBytes(6, encrypt("Healthy", key1));
	    prep.setBytes(7, encrypt("None", key1));
	    prep.setBytes(8, encrypt("", key1));
	    prep.addBatch();
	    
	    prep.setString(1, "2");
	    prep.setString(2, "Doctor2");
	    prep.setBytes(3, encrypt("Patient2", key2));
	    prep.setBytes(4, encrypt("125", key2));
	    prep.setBytes(5, encrypt("1160", key2));
	    prep.setBytes(6, encrypt("Dead", key2));
	    prep.setBytes(7, encrypt("Everything", key2));
	    prep.setBytes(8, encrypt("Condolences", key2));
	    prep.addBatch();

	    conn.setAutoCommit(false);
	    prep.executeBatch();
	    conn.setAutoCommit(true);
	    
	   
	    
	    Class.forName("org.sqlite.JDBC");
        Connection conn2 = DriverManager.getConnection("jdbc:sqlite:ks.db");
        Statement stat2 = conn2.createStatement();
        stat2.executeUpdate("drop table if exists keys;");
        stat2.executeUpdate("create table keys (userId, key);");
        
        PreparedStatement prep2 = conn2.prepareStatement(
        "insert into keys values (?, ?);");

	    prep2.setString(1, "1");
	    prep2.setBytes(2, key1);
	    prep2.addBatch();
	    prep2.setString(1, "2");
	    prep2.setBytes(2, key2);
	    prep2.addBatch();
	    
	    
	    conn2.setAutoCommit(false);
	    prep2.executeBatch();
	    conn2.setAutoCommit(true);
                
//		ResultSet rs = stat.executeQuery("select * from records;");
//		ResultSet rs2 = stat2.executeQuery("select * from keys;");
//
//		while (rs.next() && rs2.next()) {
//			System.out.println(rs.getString("age"));
//			System.out
//					.println(decrypt(rs.getBytes("age"), rs2.getBytes("key")));
//		}
//	    conn.close();
//        conn.close();
    }
       
    private static byte[] encrypt(String s, byte[] keyBytes) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        
        byte[] input = s.getBytes();
                
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
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

		return (cipherText);
	}

    @SuppressWarnings("unused")
	private static String decrypt(byte[] s, byte[] keyBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
    	Cipher cipher = Cipher.getInstance("AES", "BC");
    	// decryption pass
    	SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
        cOut.write(s);
        cOut.close();
        return new String(bOut.toByteArray());
    }
    
	private static byte[] generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(256); // 192 and 256 bits may not be available

		SecretKey skey = kgen.generateKey();
		return skey.getEncoded();
	}
    
  }