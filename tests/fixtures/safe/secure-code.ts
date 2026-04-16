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
