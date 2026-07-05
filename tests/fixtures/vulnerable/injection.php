<?php

// Vulnerable: SQL Injection (CG-001) — bare mysqli_query with concatenation
function getUser($conn, $id) {
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

// Vulnerable: SQL Injection (CG-001) — PDO->query with interpolated string
function findOrder($pdo, $id) {
    return $pdo->query("SELECT * FROM orders WHERE id = $id");
}

// Vulnerable: Command Injection (CG-002) — exec with concatenation
function listDir($dir) {
    exec("ls -la " . $dir);
}

// Vulnerable: Command Injection (CG-002) — shell_exec with concatenation
function catFile($path) {
    shell_exec("cat " . $path);
}

// Vulnerable: Code Injection (CG-003) — eval with user input
function runCode($code) {
    eval($code);
}

// Vulnerable: Hardcoded Credentials (CG-020)
function connect() {
    $password = "SuperSecret123!";
    return $password;
}

// Vulnerable: Path Traversal (CG-030) — concatenated path
function readUpload($name) {
    return file_get_contents("/uploads/" . $name);
}

// Vulnerable: SSRF (CG-060) — concatenated URL
function fetchAvatar($userHost) {
    return curl_init("http://" . $userHost . "/avatar.png");
}
