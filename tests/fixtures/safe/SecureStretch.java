package demo;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
}
