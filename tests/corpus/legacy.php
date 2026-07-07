<?php
// Labeled precision corpus — realistic legacy PHP code.
// Ground truth annotated with trailing `codeguard-expect CG-XXX` comments.

function restoreCart() {
    return unserialize($_COOKIE["cart"]); // codeguard-expect CG-041
}

function goNext() {
    header("Location: " . $_GET["next"]); // codeguard-expect CG-025
}

function getUser($pdo, $id) {
    // Placeholders bound later via execute() — the idiomatic safe pattern.
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function legacyHash($input) {
    return md5($input); // codeguard-expect CG-021
}

function pingHost() {
    system("ping -c 1 " . $_GET["host"]); // codeguard-expect CG-002
}

function currencyFormat($amount) {
    // number_format is unrelated to any sink — must stay clean.
    return number_format($amount, 2);
}
