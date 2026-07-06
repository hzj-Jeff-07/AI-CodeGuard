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

// Vulnerable: Insecure Regular Expression / ReDoS (CG-023)
function isValidEmail(input: string) {
  return new RegExp("^([a-zA-Z0-9]+)+@").test(input);
}

// Vulnerable: NoSQL Injection (CG-024) — whole request body as filter
async function login(users: any, req: any) {
  return users.findOne(req.body);
}

// Vulnerable: Open Redirect (CG-025) — redirect target from user input
function goNext(res: any, req: any) {
  res.redirect(req.query.next);
}
