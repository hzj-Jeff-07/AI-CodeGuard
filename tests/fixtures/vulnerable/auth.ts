// Vulnerable: Hardcoded Credentials (CG-020)
const DB_PASSWORD = "super_secret_123";
const API_KEY = "sk-1234567890abcdef";
const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const secret = 'my-jwt-secret-key';

// Vulnerable: Weak Cryptography (CG-021)
import crypto from 'crypto';

function hashPassword(password: string) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function weakEncrypt(data: string, key: string) {
  return crypto.createCipher('des', key).update(data);
}

function sha1Hash(input: string) {
  return crypto.createHash('sha1').update(input).digest('hex');
}
