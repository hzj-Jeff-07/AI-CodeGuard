package demo;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletResponse;

public class SecureStretch {

    // Safe: credentials come from the environment
    public String connect() {
        String password = System.getenv("DB_PASSWORD");
        return password;
    }

    // Safe: static path
    public byte[] readConfig() throws Exception {
        return Files.readAllBytes(Paths.get("/etc/app/config.yml"));
    }

    // Safe: user path is normalized and prefix-checked before use
    public byte[] readUpload(String name) throws Exception {
        Path target = Paths.get("/data/uploads/" + name).normalize();
        if (!target.startsWith("/data/uploads")) throw new SecurityException("bad path");
        return Files.readAllBytes(target);
    }

    // Safe: static URL
    public URL healthCheck() throws Exception {
        return new URL("https://status.example.com/health");
    }

    // Safe: strong hash algorithm
    public MessageDigest hashPassword() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }

    // Safe: non-sensitive log message
    public void logStartup() {
        logger.info("server started");
    }

    // Safe: CSRF protection left enabled, cookies locked down
    public void configure(HttpSecurity http, Cookie cookie) throws Exception {
        http.csrf();
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
    }

    // Safe: static response body, not attacker-controlled input
    public void staticResponse(HttpServletResponse response) throws Exception {
        response.getWriter().write("<html>OK</html>");
    }
}
