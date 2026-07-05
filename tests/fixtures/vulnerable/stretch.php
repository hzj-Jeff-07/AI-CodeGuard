<?php

// Vulnerable: Weak Cryptography (CG-021) — bare md5()
function hashPassword($password) {
    return md5($password);
}

// Vulnerable: Sensitive Data Exposure (CG-040) — password logged
function logLogin($password) {
    error_log("login attempt with password: " . $password);
}

// Vulnerable: Insecure Deserialization (CG-041) — unserialize on untrusted input
function loadSession($data) {
    return unserialize($data);
}

// Vulnerable: Security Misconfiguration (CG-050) — TLS verification disabled
function insecureFetch($ch, $url) {
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return curl_exec($ch);
}
