// Safe: Parameterized SQL queries
import { Pool } from 'pg';

const pool = new Pool();

async function getUser(userId: string) {
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  return result.rows[0];
}

async function searchUsers(name: string) {
  const result = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
  return result.rows;
}

// Safe: No dynamic command execution
import { execSync } from 'child_process';

function runFixedCommand() {
  execSync("ls -la /tmp");
}

// Safe: No eval or dynamic code
function add(a: number, b: number) {
  return a + b;
}

function greet(name: string) {
  return `Hello, ${name}!`;
}

// Safe: no nested/overlapping quantifiers
function isValidEmail(input: string) {
  return new RegExp("^[a-zA-Z0-9]+@").test(input);
}

// Safe: querying by a specific validated field, not the whole request body
async function login(users: any, username: string) {
  return users.findOne({ username });
}

// Safe: redirect target is a fixed, known path
function goToLogin(res: any) {
  res.redirect("/login");
}

// Safe: restricted to a specific signing algorithm
function verifyToken(jwt: any, token: string, secret: string) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}
