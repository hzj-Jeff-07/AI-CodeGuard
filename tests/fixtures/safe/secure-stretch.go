package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"log"
	"net/http"
	"os"
)

// Safe: credentials come from the environment
func connect() string {
	password := os.Getenv("DB_PASSWORD")
	return password
}

// Safe: static path
func readConfig() ([]byte, error) {
	return os.ReadFile("/etc/app/config.yml")
}

// Safe: static URL
func healthCheck() (*http.Response, error) {
	return http.Get("https://status.example.com/health")
}

// Safe: strong hash algorithm
func hashPassword(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

// Safe: non-sensitive log message
func logStartup() {
	log.Println("server started")
}

// Safe: TLS verification enabled
func secureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}

// Safe: cryptographic RNG for a session token
func generateSessionToken() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
