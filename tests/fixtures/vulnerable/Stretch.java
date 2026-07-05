package demo;

import java.io.File;
import java.io.ObjectInputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Stretch {

    // Vulnerable: Hardcoded Credentials (CG-020) — field literal
    private String password = "SuperSecret123!";

    // Vulnerable: Hardcoded Credentials (CG-020) — local literal
    public String connect() {
        String apiKey = "sk-live-9f8e7d6c5b4a3210";
        return apiKey;
    }

    // Vulnerable: Path Traversal (CG-030) — concatenated path
    public File readUserFile(String name) {
        return new File("/data/uploads/" + name);
    }

    // Vulnerable: Path Traversal (CG-030) — String.format-built path
    public String openLog(String day) throws Exception {
        return Files.readString(Paths.get(String.format("/var/log/app/%s.log", day)));
    }

    // Vulnerable: SSRF (CG-060) — concatenated URL
    public URL fetchAvatar(String userHost) throws Exception {
        return new URL("http://" + userHost + "/avatar.png");
    }

    // Vulnerable: Weak Cryptography (CG-021)
    public MessageDigest hashPassword() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    // Vulnerable: Sensitive Data Exposure (CG-040) — password logged
    public void logLogin(String password) {
        logger.info("login attempt with password=" + password);
    }

    // Vulnerable: Insecure Deserialization (CG-041)
    public Object readUntrusted(ObjectInputStream ois) throws Exception {
        return ois.readObject();
    }

    // Vulnerable: Security Misconfiguration (CG-050) — CSRF disabled
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    // Vulnerable: Arbitrary File Read/Write (CG-031) — path from request parameter
    public File readRequestedFile(HttpServletRequest request) {
        return new File(request.getParameter("path"));
    }

    // Vulnerable: Cross-Site Scripting (CG-010) — unescaped reflection to response
    public void echoName(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().write(request.getParameter("name"));
    }
}
