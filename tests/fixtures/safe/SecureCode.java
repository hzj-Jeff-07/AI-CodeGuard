package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SecureCode {

    // Safe: parameterized query with placeholder
    public ResultSet getUser(Connection conn, String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    // Safe: static query
    public ResultSet countUsers(Connection conn) throws Exception {
        return conn.prepareStatement("SELECT COUNT(*) FROM users").executeQuery();
    }

    // Safe: static command with argument vector
    public ProcessBuilder listDir(String dir) {
        return new ProcessBuilder("ls", "-la", dir);
    }
}
