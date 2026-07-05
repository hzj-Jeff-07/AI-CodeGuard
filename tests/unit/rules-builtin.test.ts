import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/index.js';
import { runRules, getRules } from '../../src/rules/index.js';
import type { SuspiciousNode } from '../../src/types/index.js';

async function scanCode(source: string, lang: 'javascript' | 'typescript' | 'python' | 'go' | 'java' = 'typescript'): Promise<SuspiciousNode[]> {
  const tree = await parse(source, lang);
  const rules = getRules();
  const extMap: Record<string, string> = { python: 'py', javascript: 'js', typescript: 'ts', go: 'go', java: 'java' };
  return runRules(tree, rules, `test.${extMap[lang]}`);
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

// ── CG-001: SQL Injection (Go) ──────────────────────────────────

describe('CG-001: SQL Injection (Go)', () => {
  it('detects db.Query with inline fmt.Sprintf', async () => {
    const source = `package main
func f() {
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	_ = rows
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects fmt.Sprintf assembling SQL into a variable', async () => {
    const source = `package main
func f(name string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	rows, _ := db.Query(query)
	_ = rows
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects db.Exec with string concatenation', async () => {
    const source = `package main
func f(name string) {
	db.Exec("DELETE FROM users WHERE name = '" + name + "'")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores placeholder-parameterized Go queries', async () => {
    const source = `package main
func f(name string) {
	rows, _ := db.Query("SELECT * FROM users WHERE name = ?", name)
	db.Exec("DELETE FROM users WHERE id = $1", id)
	_ = rows
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-001').length).toBe(0);
  });
});

// ── CG-001: SQL Injection (Java) ────────────────────────────────

describe('CG-001: SQL Injection (Java)', () => {
  it('detects executeQuery with string concatenation', async () => {
    const source = `class T {
  ResultSet f(Statement stmt, String name) {
    return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects String.format assembling SQL', async () => {
    const source = `class T {
  void f(Connection conn, String name) {
    String query = String.format("DELETE FROM users WHERE name = '%s'", name);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores parameterized prepared statements', async () => {
    const source = `class T {
  ResultSet f(Connection conn, String name) {
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    return ps.executeQuery();
  }
}`;
    const results = await scanCode(source, 'java');
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

// ── CG-002: Command Injection (Go) ──────────────────────────────

describe('CG-002: Command Injection (Go)', () => {
  it('detects exec.Command with string concatenation', async () => {
    const source = `package main
func f(dir string) {
	cmd := exec.Command("sh", "-c", "ls -la "+dir)
	cmd.Output()
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('detects exec.Command with fmt.Sprintf', async () => {
    const source = `package main
func f(host string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", host))
	cmd.Output()
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores exec.Command with argument vector', async () => {
    const source = `package main
func f(dir string) {
	cmd := exec.Command("ls", "-la", dir)
	cmd.Output()
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-002').length).toBe(0);
  });
});

// ── CG-002: Command Injection (Java) ────────────────────────────

describe('CG-002: Command Injection (Java)', () => {
  it('detects Runtime.getRuntime().exec with concatenation', async () => {
    const source = `class T {
  Process f(String dir) throws Exception {
    return Runtime.getRuntime().exec("ls -la " + dir);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('detects ProcessBuilder with concatenation', async () => {
    const source = `class T {
  ProcessBuilder f(String host) {
    return new ProcessBuilder("sh", "-c", "ping -c 1 " + host);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores ProcessBuilder with argument vector', async () => {
    const source = `class T {
  ProcessBuilder f(String dir) {
    return new ProcessBuilder("ls", "-la", dir);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-002').length).toBe(0);
  });
});

// ── Go stretch rules: CG-020 / CG-030 / CG-060 ──────────────────

describe('CG-020: Hardcoded Credentials (Go)', () => {
  it('detects short variable declaration with password literal', async () => {
    const source = `package main
func f() string {
	password := "SuperSecret123!"
	return password
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('detects const api key', async () => {
    const source = `package main
const apiKey = "sk-live-9f8e7d6c5b4a3210"`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores credentials read from the environment', async () => {
    const source = `package main
func f() string {
	password := os.Getenv("DB_PASSWORD")
	return password
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-020').length).toBe(0);
  });
});

describe('CG-030: Path Traversal (Go)', () => {
  it('detects os.ReadFile with concatenated path', async () => {
    const source = `package main
func f(name string) ([]byte, error) {
	return os.ReadFile("/data/uploads/" + name)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('detects os.Open with Sprintf-built path', async () => {
    const source = `package main
func f(day string) (*os.File, error) {
	return os.Open(fmt.Sprintf("/var/log/%s.log", day))
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static paths', async () => {
    const source = `package main
func f() ([]byte, error) {
	return os.ReadFile("/etc/app/config.yml")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });

  it('ignores non-os objects with matching method names', async () => {
    const source = `package main
func f(bucket Bucket, name string) ([]byte, error) {
	return bucket.ReadFile("prefix/" + name)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });
});

describe('CG-060: SSRF (Go)', () => {
  it('detects http.Get with concatenated URL', async () => {
    const source = `package main
func f(host string) (*http.Response, error) {
	return http.Get("http://" + host + "/avatar.png")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('detects http.Get with Sprintf-built URL', async () => {
    const source = `package main
func f(endpoint string) (*http.Response, error) {
	return http.Get(fmt.Sprintf("http://internal/%s", endpoint))
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static URLs', async () => {
    const source = `package main
func f() (*http.Response, error) {
	return http.Get("https://status.example.com/health")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-060').length).toBe(0);
  });
});

// ── Java stretch rules: CG-020 / CG-030 / CG-060 ────────────────

describe('CG-020: Hardcoded Credentials (Java)', () => {
  it('detects field with password literal', async () => {
    const source = `class T {
  private String password = "SuperSecret123!";
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('detects local api key literal', async () => {
    const source = `class T {
  String f() {
    String apiKey = "sk-live-9f8e7d6c5b4a3210";
    return apiKey;
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores credentials read from the environment', async () => {
    const source = `class T {
  String f() {
    String password = System.getenv("DB_PASSWORD");
    return password;
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-020').length).toBe(0);
  });
});

describe('CG-030: Path Traversal (Java)', () => {
  it('detects new File with concatenated path', async () => {
    const source = `class T {
  File f(String name) {
    return new File("/data/uploads/" + name);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('detects Files helper with String.format-built path', async () => {
    const source = `class T {
  String f(String day) throws Exception {
    return Files.readString(Paths.get(String.format("/var/log/%s.log", day)));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static paths', async () => {
    const source = `class T {
  byte[] f() throws Exception {
    return Files.readAllBytes(Paths.get("/etc/app/config.yml"));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });

  it('ignores paths normalized and prefix-checked', async () => {
    const source = `class T {
  byte[] f(String name) throws Exception {
    Path target = Paths.get("/data/uploads/" + name).normalize();
    if (!target.startsWith("/data/uploads")) throw new SecurityException("bad path");
    return Files.readAllBytes(target);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });

  it('ignores non-file objects with matching method names', async () => {
    const source = `class T {
  String f(Map<String, String> map, String key) {
    return map.get("prefix-" + key);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });
});

describe('CG-060: SSRF (Java)', () => {
  it('detects new URL with concatenated host', async () => {
    const source = `class T {
  URL f(String host) throws Exception {
    return new URL("http://" + host + "/avatar.png");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('detects RestTemplate call with String.format-built URL', async () => {
    const source = `class T {
  String f(RestTemplate restTemplate, String endpoint) {
    return restTemplate.getForObject(String.format("http://internal-api/%s", endpoint), String.class);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static URLs', async () => {
    const source = `class T {
  URL f() throws Exception {
    return new URL("https://status.example.com/health");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-060').length).toBe(0);
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
