package demo;

// Labeled precision corpus — realistic Java service code.
// Ground truth annotated with trailing `codeguard-expect CG-XXX` comments.

import java.security.MessageDigest;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Service {

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding"); // codeguard-expect CG-021
    }

    public MessageDigest strongDigest() throws Exception {
        // SHA-256 — safe.
        return MessageDigest.getInstance("SHA-256");
    }

    public void findUser(Statement stmt, HttpServletRequest request) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + request.getParameter("name") + "'"); // codeguard-expect CG-001
    }

    public void redirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("url")); // codeguard-expect CG-025
    }

    public void log(HttpServletRequest request) {
        // Non-sensitive value — must stay clean.
        logger.info("request path: " + request.getRequestURI());
    }
}
