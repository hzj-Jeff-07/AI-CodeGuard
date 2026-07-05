package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
)

// Vulnerable: Hardcoded Credentials (CG-020)
const apiKey = "sk-live-9f8e7d6c5b4a3210"

func connect() string {
	password := "SuperSecret123!"
	return password
}

// Vulnerable: Path Traversal (CG-030) — concatenated path
func readUserFile(name string) ([]byte, error) {
	return os.ReadFile("/data/uploads/" + name)
}

// Vulnerable: Path Traversal (CG-030) — Sprintf-built path
func openLog(day string) (*os.File, error) {
	return os.Open(fmt.Sprintf("/var/log/app/%s.log", day))
}

// Vulnerable: SSRF (CG-060) — concatenated URL
func fetchAvatar(userHost string) (*http.Response, error) {
	return http.Get("http://" + userHost + "/avatar.png")
}

// Vulnerable: SSRF (CG-060) — Sprintf-built URL
func callService(endpoint string) (*http.Response, error) {
	return http.Get(fmt.Sprintf("http://internal-api/%s", endpoint))
}

// Vulnerable: Weak Cryptography (CG-021) — crypto/md5
func hashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}

// Vulnerable: Sensitive Data Exposure (CG-040) — password logged
func logLogin(password string) {
	log.Printf("login attempt with password: %s", password)
}

// Vulnerable: Security Misconfiguration (CG-050) — TLS verification disabled
func insecureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
