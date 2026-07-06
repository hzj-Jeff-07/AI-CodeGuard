package main

// Labeled precision corpus — realistic Go HTTP handlers.
// Ground truth annotated with trailing `codeguard-expect CG-XXX` comments.

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func getUser(w http.ResponseWriter, r *http.Request) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", r.URL.Query().Get("id")) // codeguard-expect CG-001
	rows, _ := db.Query(query)
	_ = rows
}

func getUserSafe(w http.ResponseWriter, r *http.Request) {
	// Placeholder-based — safe.
	rows, _ := db.Query("SELECT * FROM users WHERE id = $1", r.URL.Query().Get("id"))
	_ = rows
}

func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), 302) // codeguard-expect CG-025
}

func runTool(w http.ResponseWriter, r *http.Request) {
	// Command passed by variable, no inline concatenation — Stage 1 cannot
	// trace the flow, so this is a known miss (honest FN).
	tool := r.FormValue("tool")
	cmd := exec.Command("sh", "-c", tool) // codeguard-expect CG-002
	_ = cmd
}

func readConfig() ([]byte, error) {
	// Static path — safe.
	return os.ReadFile("/etc/app/config.yml")
}
