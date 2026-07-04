package main

import (
	"database/sql"
	"os/exec"
)

// Safe: parameterized query with placeholder
func getUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}

// Safe: parameterized exec
func deleteUser(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
	return err
}

// Safe: static command with argument vector (no shell, no concatenation)
func listDir(dir string) ([]byte, error) {
	cmd := exec.Command("ls", "-la", dir)
	return cmd.Output()
}

// Safe: static query
func countUsers(db *sql.DB) (*sql.Row, error) {
	return db.QueryRow("SELECT COUNT(*) FROM users"), nil
}
