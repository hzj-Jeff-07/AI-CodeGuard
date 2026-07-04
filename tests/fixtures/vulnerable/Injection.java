package demo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Injection {

    // Vulnerable: SQL Injection (CG-001) — string concatenation
    public ResultSet getUser(Statement stmt, String name) throws Exception {
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    // Vulnerable: SQL Injection (CG-001) — String.format assembly
    public ResultSet findOrder(Statement stmt, String id) throws Exception {
        return stmt.executeQuery(String.format("SELECT * FROM orders WHERE id = %s", id));
    }

    // Vulnerable: SQL Injection (CG-001) — two-step String.format
    public void deleteUser(Connection conn, String name) throws Exception {
        String query = String.format("DELETE FROM users WHERE name = '%s'", name);
        conn.prepareStatement(query).execute();
    }

    // Vulnerable: Command Injection (CG-002) — Runtime.exec with concatenation
    public Process runTool(String dir) throws Exception {
        return Runtime.getRuntime().exec("ls -la " + dir);
    }

    // Vulnerable: Command Injection (CG-002) — ProcessBuilder with concatenation
    public ProcessBuilder ping(String host) {
        return new ProcessBuilder("sh", "-c", "ping -c 1 " + host);
    }
}
