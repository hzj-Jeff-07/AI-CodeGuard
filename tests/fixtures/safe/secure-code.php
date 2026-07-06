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

// Safe: strong hash algorithm
function hashPassword($password) {
    return hash('sha256', $password);
}

// Safe: non-sensitive log message
function logStartup() {
    error_log("service started");
}

// Safe: TLS verification enabled
function secureFetch($ch, $url) {
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    return curl_exec($ch);
}

// Safe: cryptographic RNG for an API key
function generateApiKey() {
    return bin2hex(random_bytes(16));
}

// Safe: no nested/overlapping quantifiers
function isValidEmail($value) {
    return preg_match("/^[a-zA-Z0-9]+@/", $value);
}
