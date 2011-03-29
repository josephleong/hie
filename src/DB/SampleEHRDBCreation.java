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

public class SampleEHRDBCreation {


	private static byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
//	private static byte[] ivBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
//	        0x00, 0x00, 0x00, 0x00, 0x01 };

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
    
    
    
    private static byte[] encrypt(String s) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        
        byte[] input = s.getBytes();
        
        
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
//        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
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

    private static String decrypt(byte[] s) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
    	Cipher cipher = Cipher.getInstance("AES", "BC");
    	// decryption pass
    	SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
//        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
        cOut.write(s);
        cOut.close();
        return new String(bOut.toByteArray());
    }
    
  }