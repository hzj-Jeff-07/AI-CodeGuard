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

// Vulnerable: Insecure Randomness (CG-022) — mt_rand() for an API key
function generateApiKey() {
    return mt_rand(100000, 999999);
}

// Vulnerable: Insecure Regular Expression / ReDoS (CG-023)
function isValidEmail($value) {
    return preg_match("/^([a-zA-Z0-9]+)+@/", $value);
}

// Vulnerable: NoSQL Injection (CG-024) — whole superglobal as filter
function login($collection) {
    return $collection->findOne($_POST);
}

// Vulnerable: Open Redirect (CG-025) — redirect target from $_GET
function goNext() {
    header("Location: " . $_GET["next"]);
}

// Vulnerable: JWT Signature Bypass (CG-026) — accepts the "none" algorithm
function verifyToken($jwt, $key) {
    return JWT::decode($jwt, $key, ['none']);
}

// Vulnerable: XML External Entity (CG-070) — entity substitution flag
function parseXml($data) {
    return simplexml_load_string($data, "SimpleXMLElement", LIBXML_NOENT);
}
