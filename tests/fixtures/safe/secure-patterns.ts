// Safe: Using textContent instead of innerHTML
function displayMessage(text: string) {
  document.getElementById('output')!.textContent = text;
}

// Safe: Proper crypto
import crypto from 'crypto';

function hashPassword(password: string) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Safe: Environment variables for secrets
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// Safe: Validated file paths
import fs from 'fs';
import path from 'path';

function readUserFile(filename: string) {
  const safePath = path.resolve('/uploads', filename);
  if (!safePath.startsWith('/uploads')) {
    throw new Error('Invalid path');
  }
  return fs.readFileSync(safePath, 'utf-8');
}

// Safe: Fixed URL
async function fetchData() {
  return fetch('https://api.example.com/data');
}

// Safe: Proper cookie config
import express from 'express';
const app = express();
app.use((req, res, next) => {
  res.cookie('session', 'abc', { secure: true, httpOnly: true, sameSite: 'Strict' });
  next();
});

// Safe: cryptographic RNG for a security token
import { randomBytes } from 'crypto';

function generateSessionToken() {
  return randomBytes(32).toString('hex');
}

// Safe: Math.random() used for non-security jitter
function retryDelay() {
  return Math.random() * 1000;
}
