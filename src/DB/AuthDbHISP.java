package DB;
import java.math.BigInteger;
import java.sql.Connection;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.*;

public class AuthDbHISP {
    public static void main(String[] args) throws Exception {
    	
    	String plaintext = "password1";
    	MessageDigest m = MessageDigest.getInstance("MD5");
    	m.reset();
    	m.update(plaintext.getBytes());
    	byte[] digest = m.digest();
    	BigInteger bigInt = new BigInteger(1,digest);
    	String hashtext = bigInt.toString(16);
    	String plaintext2 = "password2";
    	MessageDigest m2 = MessageDigest.getInstance("MD5");
    	m2.reset();
    	m2.update(plaintext2.getBytes());
    	byte[] digest2 = m2.digest();
    	BigInteger bigInt2 = new BigInteger(1,digest2);
    	String hashtext2 = bigInt2.toString(16);
    	
    	
        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:HISP.db");
        Statement stat = conn.createStatement();
        stat.executeUpdate("drop table if exists users;");
        stat.executeUpdate("create table users (username, password, type);");
        PreparedStatement prep = conn.prepareStatement(
            "insert into users values (?, ?, ?);");

        prep.setString(1, "Doctor1");
        prep.setString(2, hashtext);
        prep.setString(3, "doctor");
        prep.addBatch();
        prep.setString(1, "Doctor2");
        prep.setString(2, hashtext2);
        prep.setString(3, "doctor");
        prep.addBatch();
        prep.setString(1, "Nurse1");
        prep.setString(2, hashtext);
        prep.setString(3, "nurse");
        prep.addBatch();

        conn.setAutoCommit(false);
        prep.executeBatch();
        conn.setAutoCommit(true);

        ResultSet rs = stat.executeQuery("select * from users;");
        while (rs.next()) {
            System.out.println("username = " + rs.getString("username"));
            System.out.println("password = " + rs.getString("password"));
        }
        rs.close();
        conn.close();
    }
  }
