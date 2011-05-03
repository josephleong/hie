package DB;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
/**
 * Creates a HISPagent authentication database with a few sample users
 *  @author Joseph Leong (leong1), Brett Stevens (steven10)
 *
 */
public class UserDB {
    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:user.db");
        Statement stat = conn.createStatement();
        stat.executeUpdate("drop table if exists phr;");
        stat.executeUpdate("drop table if exists hisp;");
        stat.executeUpdate("drop table if exists ra;");
        stat.executeUpdate("drop table if exists readAccess;");
        stat.executeUpdate("drop table if exists writeAccess;");
        
        stat.executeUpdate("create table phr (username, password);");
        stat.executeUpdate("create table hisp (username, password, type);");
        stat.executeUpdate("create table ra (username, password, columns, conditions);");
        stat.executeUpdate("create table readAccess (userId, agentId);");
        stat.executeUpdate("create table writeAccess (userId, agentId);");
        
    	MessageDigest m = MessageDigest.getInstance("MD5");
    	m.reset();

    	PreparedStatement prepPHR = conn.prepareStatement(
        "insert into phr values (?, ?);");
    	prepPHR.setString(1, "a");
    	m.update("a".getBytes()); // password
        prepPHR.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepPHR.addBatch();
        prepPHR.setString(1, "Patient1");
        m.update("Password1".getBytes());
        prepPHR.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepPHR.addBatch();
        prepPHR.setString(1, "Patient2");
        m.update("Password2".getBytes());
        prepPHR.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepPHR.addBatch();
        
        PreparedStatement prepHISP = conn.prepareStatement(
        "insert into hisp values (?, ?, ?);");
        prepHISP.setString(1, "d");
    	m.update("d".getBytes()); // password
    	prepHISP.setString(2, new BigInteger(1,m.digest()).toString(16));
    	prepHISP.setString(3, "doctor");
    	prepHISP.addBatch();
    	prepHISP.setString(1, "Doctor1");
        m.update("Password1".getBytes());
        prepHISP.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepHISP.setString(3, "doctor");
        prepHISP.addBatch();
        prepHISP.setString(1, "Doctor2");
        m.update("Password2".getBytes());
        prepHISP.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepHISP.setString(3, "doctor");
        prepHISP.addBatch();
        prepHISP.setString(1, "Nurse");
        m.update("n".getBytes());
        prepHISP.setString(2, new BigInteger(1,m.digest()).toString(16));
        prepHISP.setString(3, "nurse");
        prepHISP.addBatch();
        
        PreparedStatement prepRA = conn.prepareStatement(
        "insert into ra values (?, ?, ?, ?);");
        prepRA.setString(1, "r");
    	m.update("r".getBytes()); // password
    	prepRA.setString(2, new BigInteger(1,m.digest()).toString(16));
    	prepRA.setString(3, "age, diagnosis");
    	prepRA.setBoolean(4, true);
    	prepRA.addBatch();
    	prepRA.setString(1, "RA1");
    	m.update("Password1".getBytes()); // password
    	prepRA.setString(2, new BigInteger(1,m.digest()).toString(16));
    	prepRA.setString(3, "other, prescriptions");
    	prepRA.setBoolean(4, true);
    	prepRA.addBatch();
    	prepRA.setString(1, "RA2");
    	m.update("Password2".getBytes()); // password
    	prepRA.setString(2, new BigInteger(1,m.digest()).toString(16));
    	prepRA.setString(3, "age, weight");
    	prepRA.setString(4, "age >= 20 AND age <= 50");
    	prepRA.addBatch();
    	
    	PreparedStatement prepRead = conn.prepareStatement(
        "insert into readAccess values (?, ?);");
        prepRead.setString(1, "Patient1");
        prepRead.setString(2, "Doctor1");
        prepRead.addBatch();
        prepRead.setString(1, "Patient2");
        prepRead.setString(2, "Doctor2");
        prepRead.addBatch();
        prepRead.setString(1, "a");
        prepRead.setString(2, "d");
        prepRead.addBatch();
    	
    	PreparedStatement prepWrite = conn.prepareStatement(
        "insert into writeAccess values (?, ?);");
    	prepWrite.setString(1, "Patient1");
    	prepWrite.setString(2, "Doctor1");
    	prepWrite.addBatch();
    	prepWrite.setString(1, "Patient2");
    	prepWrite.setString(2, "Doctor2");
    	prepWrite.addBatch();
    	prepWrite.setString(1, "a");
    	prepWrite.setString(2, "d");
    	prepWrite.addBatch();
    	
        conn.setAutoCommit(false);
        prepPHR.executeBatch();
        prepHISP.executeBatch();
        prepRA.executeBatch();
        prepRead.executeBatch();
        prepWrite.executeBatch();
        conn.setAutoCommit(true);

//        m.update("a".getBytes()); 
//        System.out.println("Hash of \"a\": "+ new BigInteger(1,m.digest()).toString(16));
//        m.update("Password1".getBytes()); 
//        System.out.println("Hash of \"Password1\": "+ new BigInteger(1,m.digest()).toString(16));
//        m.update("Password2".getBytes()); 
//        System.out.println("Hash of \"Password2\": "+ new BigInteger(1,m.digest()).toString(16));
//        
//        ResultSet rs = stat.executeQuery("select columns, conditions from ra;");
//        while (rs.next()) {
//            System.out.println("columns = " + rs.getString("columns"));
//            System.out.println("conditions = " + rs.getString("conditions"));
//            System.out.println("select "+rs.getString("columns")+" from ra where " + rs.getString("conditions") +";");
//                        
//        }
//        rs.close();
        conn.close();
    }
  }
