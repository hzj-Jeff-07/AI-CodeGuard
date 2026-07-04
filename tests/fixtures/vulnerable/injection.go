package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// Vulnerable: SQL Injection (CG-001) — fmt.Sprintf query assembly
func getUser(db *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

// Vulnerable: SQL Injection (CG-001) — Sprintf inline
func findOrder(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %s", id))
	_ = rows
}

// Vulnerable: SQL Injection (CG-001) — string concatenation
func deleteUser(db *sql.DB, name string) error {
	_, err := db.Exec("DELETE FROM users WHERE name = '" + name + "'")
	return err
}

// Vulnerable: Command Injection (CG-002) — concatenated shell command
func runTool(dir string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "ls -la "+dir)
	return cmd.Output()
}

// Vulnerable: Command Injection (CG-002) — Sprintf-built command
func ping(host string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", host))
	return cmd.Output()
}
