package main

import (
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
