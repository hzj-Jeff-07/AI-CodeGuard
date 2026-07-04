import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/index.js';
import { runRules, getRules } from '../../src/rules/index.js';
import type { SuspiciousNode } from '../../src/types/index.js';

async function scanCode(source: string, lang: 'javascript' | 'typescript' | 'python' = 'typescript'): Promise<SuspiciousNode[]> {
  const tree = await parse(source, lang);
  const rules = getRules();
  return runRules(tree, rules, `test.${lang === 'python' ? 'py' : lang === 'javascript' ? 'js' : 'ts'}`);
}

function findByRule(results: SuspiciousNode[], ruleId: string): SuspiciousNode[] {
  return results.filter(r => r.ruleId === ruleId);
}

// ── CG-001: SQL Injection ───────────────────────────────────────

describe('CG-001: SQL Injection', () => {
  it('detects template literal SQL', async () => {
    const results = await scanCode('pool.query(`SELECT * FROM users WHERE id = ${id}`)');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects multiline template literal SQL', async () => {
    const results = await scanCode('pool.query(\n  `SELECT * FROM users WHERE id = ${id}`\n)');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects string concatenation SQL', async () => {
    const results = await scanCode('db.query("SELECT * FROM users WHERE id = " + userId)');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores parameterized queries', async () => {
    const results = await scanCode('db.query("SELECT * FROM users WHERE id = ?", [userId])');
    expect(findByRule(results, 'CG-001').length).toBe(0);
  });

  it('ignores non-SQL method calls', async () => {
    const results = await scanCode('console.log(`hello ${name}`)');
    expect(findByRule(results, 'CG-001').length).toBe(0);
  });
});

// ── CG-002: Command Injection ───────────────────────────────────

describe('CG-002: Command Injection', () => {
  it('detects exec with template literal', async () => {
    const results = await scanCode('child_process.exec(`rm -rf ${dir}`)');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('detects execSync with string concat', async () => {
    const results = await scanCode('child_process.execSync("ping " + host)');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static commands', async () => {
    const results = await scanCode('child_process.exec("ls -la")');
    expect(findByRule(results, 'CG-002').length).toBe(0);
  });
});

// ── CG-003: Code Injection ──────────────────────────────────────

describe('CG-003: Code Injection', () => {
  it('detects eval()', async () => {
    const results = await scanCode('eval(userInput)');
    expect(findByRule(results, 'CG-003').length).toBeGreaterThanOrEqual(1);
  });

  it('detects new Function()', async () => {
    const results = await scanCode('new Function("return " + code)');
    expect(findByRule(results, 'CG-003').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores non-eval functions', async () => {
    const results = await scanCode('myFunction(x)');
    expect(findByRule(results, 'CG-003').length).toBe(0);
  });
});

// ── CG-010: XSS ────────────────────────────────────────────────

describe('CG-010: Cross-Site Scripting (XSS)', () => {
  it('detects innerHTML in function call context', async () => {
    const results = await scanCode('render(element.innerHTML)');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('detects document.write', async () => {
    const results = await scanCode('document.write(data)');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores textContent', async () => {
    const results = await scanCode('element.textContent = userInput');
    expect(findByRule(results, 'CG-010').length).toBe(0);
  });

  it('does not match on program root node', async () => {
    const results = await scanCode('// safe: textContent not innerHTML\nconst x = 1;');
    expect(findByRule(results, 'CG-010').length).toBe(0);
  });
});

// ── CG-011: DOM-based XSS ──────────────────────────────────────

describe('CG-011: DOM-based XSS', () => {
  it('detects location.hash flowing to innerHTML in function call', async () => {
    const results = await scanCode('setHTML(element.innerHTML, location.hash)');
    expect(findByRule(results, 'CG-011').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores source-only without sink', async () => {
    const results = await scanCode('getParam(location.hash)');
    expect(findByRule(results, 'CG-011').length).toBe(0);
  });
});

// ── CG-020: Hardcoded Credentials ───────────────────────────────

describe('CG-020: Hardcoded Credentials', () => {
  it('detects hardcoded password', async () => {
    const results = await scanCode('const password = "SuperSecret123"');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('detects hardcoded API key', async () => {
    const results = await scanCode('const api_key = "sk-abcdef123456"');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores process.env references', async () => {
    const results = await scanCode('const password = process.env.PASSWORD');
    expect(findByRule(results, 'CG-020').length).toBe(0);
  });

  it('ignores placeholder values', async () => {
    const results = await scanCode('const password = "changeme"');
    expect(findByRule(results, 'CG-020').length).toBe(0);
  });
});

// ── CG-021: Weak Cryptography ───────────────────────────────────

describe('CG-021: Weak Cryptography', () => {
  it('detects MD5', async () => {
    const results = await scanCode("crypto.createHash('md5')");
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('detects SHA1', async () => {
    const results = await scanCode("crypto.createHash('sha1')");
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores SHA256', async () => {
    const results = await scanCode("crypto.createHash('sha256')");
    expect(findByRule(results, 'CG-021').length).toBe(0);
  });
});

// ── CG-030: Path Traversal ──────────────────────────────────────

describe('CG-030: Path Traversal', () => {
  it('detects readFileSync with template literal path', async () => {
    const results = await scanCode('fs.readFileSync(`/data/${filename}`)');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('detects createReadStream with concat path', async () => {
    const results = await scanCode('fs.createReadStream("/uploads/" + file)');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static paths', async () => {
    const results = await scanCode('fs.readFileSync("/etc/config.json")');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });
});

// ── CG-031: Arbitrary File Access ───────────────────────────────

describe('CG-031: Arbitrary File Access', () => {
  it('detects readFile with req.query.path', async () => {
    const results = await scanCode('fs.readFile(req.query.path)');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores readFile with static path', async () => {
    const results = await scanCode('fs.readFile("config.json")');
    expect(findByRule(results, 'CG-031').length).toBe(0);
  });
});

// ── CG-040: Sensitive Data Exposure ─────────────────────────────

describe('CG-040: Sensitive Data Exposure', () => {
  it('detects logging passwords', async () => {
    const results = await scanCode('console.log(password)');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('detects logging credit card data', async () => {
    const results = await scanCode('console.log(creditCard)');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores logging non-sensitive data', async () => {
    const results = await scanCode('console.log("hello world")');
    expect(findByRule(results, 'CG-040').length).toBe(0);
  });
});

// ── CG-041: Insecure Deserialization ────────────────────────────

describe('CG-041: Insecure Deserialization', () => {
  it('detects pickle.loads in Python', async () => {
    const results = await scanCode('pickle.loads(data)', 'python');
    expect(findByRule(results, 'CG-041').length).toBeGreaterThanOrEqual(1);
  });

  it('detects yaml.load without SafeLoader in Python', async () => {
    const results = await scanCode('yaml.load(data)', 'python');
    expect(findByRule(results, 'CG-041').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores yaml.safe_load in Python', async () => {
    const results = await scanCode('yaml.safe_load(data)', 'python');
    expect(findByRule(results, 'CG-041').length).toBe(0);
  });
});

// ── CG-050: Security Misconfiguration ───────────────────────────

describe('CG-050: Security Misconfiguration', () => {
  it('detects CORS wildcard', async () => {
    const results = await scanCode('cors({ origin: "*" })');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('detects secure: false', async () => {
    const results = await scanCode('cookie({ secure: false })');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('detects rejectUnauthorized: false', async () => {
    const results = await scanCode('https.request({ rejectUnauthorized: false })');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores secure configs', async () => {
    const results = await scanCode('cookie({ secure: true, httpOnly: true })');
    expect(findByRule(results, 'CG-050').length).toBe(0);
  });

  it('does not match on program root node', async () => {
    const results = await scanCode('// secure: false is just a comment\nconst x = 1;');
    expect(findByRule(results, 'CG-050').length).toBe(0);
  });
});

// ── CG-060: SSRF ────────────────────────────────────────────────

describe('CG-060: SSRF', () => {
  it('detects fetch with template literal URL', async () => {
    const results = await scanCode('fetch(`http://api.example.com/${path}`)');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('detects axios with user input', async () => {
    const results = await scanCode('axios.get(req.query.url)');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static URLs', async () => {
    const results = await scanCode('fetch("https://api.example.com/data")');
    expect(findByRule(results, 'CG-060').length).toBe(0);
  });

  it('does not flag Express route registration as SSRF', async () => {
    const results = await scanCode(
      "app.get('/view', (req, res) => { res.send(req.params.file); })",
    );
    expect(findByRule(results, 'CG-060').length).toBe(0);
  });

  it('does not flag router.post route registration as SSRF', async () => {
    const results = await scanCode(
      "router.post('/upload', (req, res) => { res.json(req.body); })",
    );
    expect(findByRule(results, 'CG-060').length).toBe(0);
  });

  it('still detects http module calls with user input', async () => {
    const results = await scanCode('http.get(req.query.url)');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });
});

// ── Integration: Fixture Scanning ───────────────────────────────

describe('Fixture scanning integration', () => {
  it('finds vulnerabilities in vulnerable TypeScript fixtures', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const fixtureDir = path.resolve(__dirname, '../fixtures/vulnerable');
    const tsFiles = fs.readdirSync(fixtureDir).filter(f => f.endsWith('.ts'));

    let totalFindings = 0;
    for (const file of tsFiles) {
      const source = fs.readFileSync(path.join(fixtureDir, file), 'utf-8');
      const results = await scanCode(source, 'typescript');
      totalFindings += results.length;
    }
    expect(totalFindings).toBeGreaterThan(0);
  });

  it('finds zero vulnerabilities in safe TypeScript fixtures', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const fixtureDir = path.resolve(__dirname, '../fixtures/safe');
    const tsFiles = fs.readdirSync(fixtureDir).filter(f => f.endsWith('.ts'));

    for (const file of tsFiles) {
      const source = fs.readFileSync(path.join(fixtureDir, file), 'utf-8');
      const results = await scanCode(source, 'typescript');
      expect(results.length).toBe(0);
    }
  });
});
