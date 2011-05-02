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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
/**
 * Creates a sample Data Store databse with a sample record
 *  @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class StoreDB {

    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:DS.db");
        Statement stat = conn.createStatement();
        stat.executeUpdate("drop table if exists records;");
        stat.executeUpdate("drop table if exists readAccess;");
        stat.executeUpdate("drop table if exists writeAccess;");
        stat.executeUpdate("create table records (userId, encryptionKeyId, owner, information);");
        stat.executeUpdate("create table readAccess (userId, agentId);");
        stat.executeUpdate("create table writeAccess (userId, agentId);");
        
        PreparedStatement prep = conn.prepareStatement(
        "insert into records values (?, ?, ?, ?);");

	    prep.setString(1, "Patient1");
	    prep.setLong(2, 1);
	    prep.setString(3, "Doctor1");
	    byte[] test = encrypt("Information Goes here!");
	    String work = decrypt(test);
	    System.out.println(work);
	    prep.setBytes(4, test);
	    prep.addBatch();

	    conn.setAutoCommit(false);
	    prep.executeBatch();
	    conn.setAutoCommit(true);
        
        
        conn.close();
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
    
  }