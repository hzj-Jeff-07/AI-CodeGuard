// Vulnerable: SQL Injection (CG-001)
import { Pool } from 'pg';

const pool = new Pool();

async function getUser(userId: string) {
  // Direct string concatenation in SQL query
  const result = await pool.query("SELECT * FROM users WHERE id = '" + userId + "'");
  return result.rows[0];
}

async function searchUsers(name: string) {
  // Template literal in SQL query
  const result = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  return result.rows;
}

// Vulnerable: Command Injection (CG-002)
import { exec, execSync } from 'child_process';

function runCommand(userInput: string) {
  exec("ls -la " + userInput);
}

function pingHost(host: string) {
  execSync(`ping -c 4 ${host}`);
}

// Vulnerable: Code Injection (CG-003)
function processExpression(expr: string) {
  return eval(expr);
}

function createHandler(code: string) {
  return new Function("data", code);
}
