package DB;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

import Server.Crypto;
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
               
        byte[] key1 = Crypto.generateAESKey();
        byte[] key2 = Crypto.generateAESKey();
        byte[] key3 = Crypto.generateAESKey();
                
        PreparedStatement prep = conn.prepareStatement(
        "insert into records values (?, ?, ?, ?, ?, ?, ?, ?);");

	    prep.setString(1, "Patient1");
	    prep.setString(2, "Doctor1");
	    prep.setBytes(3, Crypto.encrypt("John", key1));
	    prep.setBytes(4, Crypto.encrypt("25", key1));
	    prep.setBytes(5, Crypto.encrypt("160", key1));
	    prep.setBytes(6, Crypto.encrypt("Healthy", key1));
	    prep.setBytes(7, Crypto.encrypt("None", key1));
	    prep.setBytes(8, Crypto.encrypt("", key1));
	    prep.addBatch();
	    
	    prep.setString(1, "Patient2");
	    prep.setString(2, "Doctor2");
	    prep.setBytes(3, Crypto.encrypt("Jack", key2));
	    prep.setBytes(4, Crypto.encrypt("125", key2));
	    prep.setBytes(5, Crypto.encrypt("1160", key2));
	    prep.setBytes(6, Crypto.encrypt("Dead", key2));
	    prep.setBytes(7, Crypto.encrypt("Everything", key2));
	    prep.setBytes(8, Crypto.encrypt("Condolences", key2));
	    prep.addBatch();
	    
	    prep.setString(1, "a");
	    prep.setString(2, "Doctor2");
	    prep.setBytes(3, Crypto.encrypt("Joe", key3));
	    prep.setBytes(4, Crypto.encrypt("21", key3));
	    prep.setBytes(5, Crypto.encrypt("135", key3));
	    prep.setBytes(6, Crypto.encrypt("Healthy", key3));
	    prep.setBytes(7, Crypto.encrypt("Nothing", key3));
	    prep.setBytes(8, Crypto.encrypt("Sicko!", key3));
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

        prep2.setString(1, "a");
	    prep2.setBytes(2, key3);
	    prep2.addBatch();
	    prep2.setString(1, "Patient1");
	    prep2.setBytes(2, key1);
	    prep2.addBatch();
	    prep2.setString(1, "Patient2");
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
          
}