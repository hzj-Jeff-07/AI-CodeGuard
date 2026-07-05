<?php

// Safe: parameterized query via PDO placeholders
function getUser($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetchAll();
}

// Safe: static command, no dynamic content
function listDir() {
    exec("ls -la", $output);
    return $output;
}

// Safe: credentials come from the environment
function connect() {
    $password = getenv("DB_PASSWORD");
    return $password;
}

// Safe: static path
function readConfig() {
    return file_get_contents("/etc/app/config.yml");
}

// Safe: static URL
function healthCheck() {
    return curl_init("https://status.example.com/health");
}
