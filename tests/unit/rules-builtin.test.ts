import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/index.js';
import { runRules, getRules } from '../../src/rules/index.js';
import type { SuspiciousNode } from '../../src/types/index.js';

async function scanCode(source: string, lang: 'javascript' | 'typescript' | 'python' | 'go' | 'java' | 'php' = 'typescript'): Promise<SuspiciousNode[]> {
  const tree = await parse(source, lang);
  const rules = getRules();
  const extMap: Record<string, string> = { python: 'py', javascript: 'js', typescript: 'ts', go: 'go', java: 'java', php: 'php' };
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

  it('ignores a call to an unrelated bare function named like a Python subprocess helper', async () => {
    // Regression guard: isPyCmd must not match Go just because a bare
    // function CALL happens to share a name with Python's subprocess API.
    const source = `package main
func build(target string) string {
	return run("building " + target)
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

// ── CG-024: NoSQL Injection ──────────────────────────────────────

describe('CG-024: NoSQL Injection', () => {
  it('detects the whole request body passed as a MongoDB filter', async () => {
    const results = await scanCode('users.find(req.body)');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('detects the whole request query object passed to findOne', async () => {
    const results = await scanCode('users.findOne(req.query)');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('detects a dynamically-built $where clause', async () => {
    const results = await scanCode('users.find({ $where: "this.name == \'" + name + "\'" })');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a specific field access from the request', async () => {
    const results = await scanCode('users.find(req.body.username)');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });

  it('ignores a static filter object', async () => {
    const results = await scanCode('users.find({ active: true })');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });

  it('detects the whole request body passed as an update document', async () => {
    // Mass-assignment via the *second* argument of updateOne: an attacker
    // can inject $set/$rename operators through an unvalidated update doc,
    // even when the filter (first argument) is perfectly safe.
    const results = await scanCode('users.updateOne({ _id: id }, req.body)');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a static update document', async () => {
    const results = await scanCode('users.updateOne({ _id: id }, { active: true })');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });

  it('does not flag $where when the dynamic content belongs to an unrelated sibling field', async () => {
    const results = await scanCode('users.find({ $where: "this.active == true", note: `hi ${x}` })');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });

  it('reduces confidence for the ambiguous find() name without other Mongo evidence', async () => {
    const results = await scanCode('logs.find(req.query)');
    const findings = findByRule(results, 'CG-024');
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].confidence).toBeLessThan(0.7);
  });
});

describe('CG-024: NoSQL Injection (Python)', () => {
  it('detects the whole request.json passed as a filter', async () => {
    const results = await scanCode('users.find(request.json)', 'python');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it("detects pymongo's snake_case find_one", async () => {
    // Regression guard: pymongo uses snake_case (find_one), not the
    // camelCase (findOne) the JS/PHP MongoDB drivers use.
    const results = await scanCode('users.find_one(request.json)', 'python');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a specific field access from the request', async () => {
    const results = await scanCode('users.find_one(request.json["id"])', 'python');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });
});

describe('CG-024: NoSQL Injection (PHP)', () => {
  it('detects the whole $_GET superglobal passed as a filter', async () => {
    const results = await scanCode('<?php $collection->find($_GET);', 'php');
    expect(findByRule(results, 'CG-024').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a specific field access from $_GET', async () => {
    const results = await scanCode('<?php $collection->find($_GET["id"]);', 'php');
    expect(findByRule(results, 'CG-024').length).toBe(0);
  });
});

// ── CG-025: Open Redirect ─────────────────────────────────────────

describe('CG-025: Open Redirect', () => {
  it('detects res.redirect with a query parameter', async () => {
    const results = await scanCode('res.redirect(req.query.url)');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores res.redirect with a static path', async () => {
    const results = await scanCode('res.redirect("/login")');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });

  it('ignores an unrelated res.status call', async () => {
    const results = await scanCode('res.status(req.query.code)');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });

  it('detects a chained res.status(...).redirect(...) call', async () => {
    const results = await scanCode('res.status(302).redirect(req.query.url)');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });
});

describe('CG-025: Open Redirect (Python)', () => {
  it("detects Flask's redirect() with a query parameter", async () => {
    const results = await scanCode('redirect(request.args.get("next"))', 'python');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores redirect() with a static path', async () => {
    const results = await scanCode('redirect("/login")', 'python');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });
});

describe('CG-025: Open Redirect (Go)', () => {
  it('detects http.Redirect with a query parameter', async () => {
    const source = `package main
func f(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores http.Redirect with a static path', async () => {
    const source = `package main
func f(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", 302)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });
});

describe('CG-025: Open Redirect (Java)', () => {
  it('detects sendRedirect with a request parameter', async () => {
    const source = `class T {
  void f(HttpServletRequest request, HttpServletResponse response) throws Exception {
    response.sendRedirect(request.getParameter("next"));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores sendRedirect with a static path', async () => {
    const source = `class T {
  void f(HttpServletResponse response) throws Exception {
    response.sendRedirect("/login");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });
});

describe('CG-025: Open Redirect (PHP)', () => {
  it('detects a Location header built from $_GET', async () => {
    const results = await scanCode('<?php header("Location: " . $_GET["next"]);', 'php');
    expect(findByRule(results, 'CG-025').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a static Location header', async () => {
    const results = await scanCode('<?php header("Location: /login");', 'php');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });

  it('ignores an unrelated header() call', async () => {
    const results = await scanCode('<?php header("Content-Type: " . $_GET["type"]);', 'php');
    expect(findByRule(results, 'CG-025').length).toBe(0);
  });
});

// ── CG-026: JWT Signature Bypass ──────────────────────────────────

describe('CG-026: JWT Signature Bypass', () => {
  it('detects algorithms: ["none"] in jwt.verify', async () => {
    const results = await scanCode("jwt.verify(token, secret, { algorithms: ['none'] })");
    expect(findByRule(results, 'CG-026').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a specific safe algorithm', async () => {
    const results = await scanCode("jwt.verify(token, secret, { algorithms: ['HS256'] })");
    expect(findByRule(results, 'CG-026').length).toBe(0);
  });

  it('detects "none" listed alongside a real algorithm', async () => {
    // The allow-list `['HS256', 'none']` still accepts an unsigned token, so
    // "none" appearing anywhere in the array is exploitable — not just first.
    const results = await scanCode("jwt.verify(token, secret, { algorithms: ['HS256', 'none'] })");
    expect(findByRule(results, 'CG-026').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a multi-algorithm allow-list without "none"', async () => {
    const results = await scanCode("jwt.verify(token, secret, { algorithms: ['HS256', 'RS256'] })");
    expect(findByRule(results, 'CG-026').length).toBe(0);
  });
});

describe('CG-026: JWT Signature Bypass (Python)', () => {
  it('detects verify_signature disabled in jwt.decode', async () => {
    const results = await scanCode('jwt.decode(token, key, options={"verify_signature": False})', 'python');
    expect(findByRule(results, 'CG-026').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a normal decode with an algorithms allowlist', async () => {
    const results = await scanCode('jwt.decode(token, key, algorithms=["HS256"])', 'python');
    expect(findByRule(results, 'CG-026').length).toBe(0);
  });
});

describe('CG-026: JWT Signature Bypass (PHP)', () => {
  it('detects JWT::decode allowing the none algorithm', async () => {
    const results = await scanCode("<?php $decoded = JWT::decode($jwt, $key, ['none']);", 'php');
    expect(findByRule(results, 'CG-026').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores JWT::decode with a specific safe algorithm', async () => {
    const results = await scanCode("<?php $decoded = JWT::decode($jwt, $key, ['HS256']);", 'php');
    expect(findByRule(results, 'CG-026').length).toBe(0);
  });

  it('ignores an unrelated decode() call mentioning none', async () => {
    const results = await scanCode("<?php $x = Cipher::decode($data, 'none');", 'php');
    expect(findByRule(results, 'CG-026').length).toBe(0);
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

describe('CG-010: Cross-Site Scripting (XSS) (Python)', () => {
  it('detects mark_safe with a variable argument', async () => {
    const results = await scanCode('mark_safe(user_input)', 'python');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('detects Markup with an f-string argument', async () => {
    const results = await scanCode('Markup(f"<b>{name}</b>")', 'python');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('detects render_template_string with a variable template', async () => {
    const results = await scanCode('render_template_string(user_template)', 'python');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores mark_safe with a static string literal', async () => {
    const results = await scanCode('mark_safe("<b>Bold</b>")', 'python');
    expect(findByRule(results, 'CG-010').length).toBe(0);
  });
});

describe('CG-010: Cross-Site Scripting (XSS) (Java)', () => {
  it('detects response.getWriter().write(request.getParameter(...))', async () => {
    const source = `class T {
  void f(HttpServletResponse response, HttpServletRequest request) throws Exception {
    response.getWriter().write(request.getParameter("name"));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores response.getWriter().write with a static string literal', async () => {
    const source = `class T {
  void f(HttpServletResponse response) throws Exception {
    response.getWriter().write("<html>OK</html>");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-010').length).toBe(0);
  });

  it('detects the two-step PrintWriter idiom (assignment, then println elsewhere)', async () => {
    // Regression guard: the sink check previously required "getWriter" to
    // appear textually in the same call expression, missing the standard
    // JSP/servlet idiom of assigning the writer to a variable first.
    const source = `class T {
  void f(HttpServletResponse response, HttpServletRequest request) throws Exception {
    PrintWriter out = response.getWriter();
    out.println(request.getParameter("name"));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-010').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a zero-argument println on the response writer', async () => {
    const source = `class T {
  void f(HttpServletResponse response) throws Exception {
    response.getWriter().println();
  }
}`;
    const results = await scanCode(source, 'java');
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

describe('CG-021: Weak Cryptography (Go)', () => {
  it('detects crypto/md5 package usage', async () => {
    const source = `package main
func f(data []byte) [16]byte {
	return md5.Sum(data)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('detects crypto/des cipher construction', async () => {
    const source = `package main
func f(key []byte) {
	des.NewCipher(key)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores crypto/sha256', async () => {
    const source = `package main
func f(data []byte) [32]byte {
	return sha256.Sum256(data)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-021').length).toBe(0);
  });
});

describe('CG-021: Weak Cryptography (Java)', () => {
  it('detects MessageDigest.getInstance("MD5")', async () => {
    const source = `class T {
  MessageDigest f() throws Exception {
    return MessageDigest.getInstance("MD5");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('detects Cipher.getInstance("DES")', async () => {
    const source = `class T {
  Cipher f() throws Exception {
    return Cipher.getInstance("DES");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores MessageDigest.getInstance("SHA-256")', async () => {
    const source = `class T {
  MessageDigest f() throws Exception {
    return MessageDigest.getInstance("SHA-256");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-021').length).toBe(0);
  });
});

describe('CG-021: Weak Cryptography (PHP)', () => {
  it('detects bare md5()', async () => {
    const results = await scanCode('<?php $h = md5($password);', 'php');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it('detects bare sha1()', async () => {
    const results = await scanCode('<?php $h = sha1($password);', 'php');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it("detects hash('md5', ...)", async () => {
    const results = await scanCode("<?php $h = hash('md5', $password);", 'php');
    expect(findByRule(results, 'CG-021').length).toBeGreaterThanOrEqual(1);
  });

  it("ignores hash('sha256', ...)", async () => {
    const results = await scanCode("<?php $h = hash('sha256', $password);", 'php');
    expect(findByRule(results, 'CG-021').length).toBe(0);
  });
});

// ── CG-022: Insecure Randomness ──────────────────────────────────

describe('CG-022: Insecure Randomness', () => {
  it('detects Math.random() used to build a token', async () => {
    const results = await scanCode('const token = Math.random().toString(36);');
    expect(findByRule(results, 'CG-022').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores Math.random() used for non-security sampling', async () => {
    const results = await scanCode('const jitter = Math.random() * 100;');
    expect(findByRule(results, 'CG-022').length).toBe(0);
  });
});

describe('CG-022: Insecure Randomness (Python)', () => {
  it('detects random.choice() used to build a password', async () => {
    const source = `import random
def gen_password():
    password = random.choice(chars)
    return password`;
    const results = await scanCode(source, 'python');
    expect(findByRule(results, 'CG-022').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores random.choice() in a non-security context', async () => {
    const source = `import random
def pick_color():
    return random.choice(colors)`;
    const results = await scanCode(source, 'python');
    expect(findByRule(results, 'CG-022').length).toBe(0);
  });
});

describe('CG-022: Insecure Randomness (Go)', () => {
  it('detects rand.Intn() used to build a session ID', async () => {
    const source = `package main
func generateSessionID() int {
	return rand.Intn(1000000)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-022').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores rand.Intn() in a non-security context', async () => {
    const source = `package main
func rollDice() int {
	return rand.Intn(6)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-022').length).toBe(0);
  });
});

describe('CG-022: Insecure Randomness (Java)', () => {
  it('detects new Random() used to build a password reset token', async () => {
    const source = `class T {
  String generateResetToken() {
    Random random = new Random();
    return String.valueOf(random.nextLong());
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-022').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores new SecureRandom()', async () => {
    const source = `class T {
  String generateResetToken() {
    SecureRandom random = new SecureRandom();
    return String.valueOf(random.nextLong());
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-022').length).toBe(0);
  });
});

describe('CG-022: Insecure Randomness (PHP)', () => {
  it('detects mt_rand() used to build an API key', async () => {
    const results = await scanCode('<?php $apiKey = mt_rand(100000, 999999);', 'php');
    expect(findByRule(results, 'CG-022').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores rand() in a non-security context', async () => {
    const results = await scanCode('<?php $diceRoll = rand(1, 6);', 'php');
    expect(findByRule(results, 'CG-022').length).toBe(0);
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

  it('detects readFile when the path variable was assigned from req.query nearby', async () => {
    const results = await scanCode('const p = req.query.path;\nfs.readFile(p);');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores readFile when the path variable was assigned from a static literal', async () => {
    const results = await scanCode('const p = "config.json";\nfs.readFile(p);');
    expect(findByRule(results, 'CG-031').length).toBe(0);
  });
});

describe('CG-031: Arbitrary File Access (Go)', () => {
  it('detects os.Open with a URL query parameter', async () => {
    const source = `package main
func f(r *http.Request) (*os.File, error) {
	return os.Open(r.URL.Query().Get("path"))
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('detects os.ReadFile with a quoted gin c.Param(...) argument', async () => {
    // Regression guard: the USER_INPUT_GO regex previously required a word
    // character immediately after `c.Param(`/`c.Query(`, which a quoted
    // string argument never satisfies — the overwhelmingly common real form.
    const source = `package main
func f(c *gin.Context) ([]byte, error) {
	return os.ReadFile(c.Param("filename"))
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores os.Open with a static path', async () => {
    const source = `package main
func f() (*os.File, error) {
	return os.Open("config.json")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-031').length).toBe(0);
  });

  it('detects os.Open when the path variable was assigned from a query param nearby', async () => {
    const source = `package main
func f(r *http.Request) (*os.File, error) {
	path := r.URL.Query().Get("path")
	return os.Open(path)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });
});

describe('CG-031: Arbitrary File Access (Java)', () => {
  it('detects new File(request.getParameter(...))', async () => {
    const source = `class T {
  File f(HttpServletRequest request) {
    return new File(request.getParameter("path"));
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores new File with a static path', async () => {
    const source = `class T {
  File f() {
    return new File("config.json");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-031').length).toBe(0);
  });

  it('detects new File when the path variable was assigned from getParameter nearby', async () => {
    const source = `class T {
  File f(HttpServletRequest request) {
    String path = request.getParameter("path");
    return new File(path);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });
});

describe('CG-031: Arbitrary File Access (PHP)', () => {
  it('detects file_get_contents with $_GET input', async () => {
    const results = await scanCode(
      '<?php $data = file_get_contents($_GET["path"]);', 'php'
    );
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores file_get_contents with a static path', async () => {
    const results = await scanCode(
      '<?php $data = file_get_contents("config.json");', 'php'
    );
    expect(findByRule(results, 'CG-031').length).toBe(0);
  });

  it('detects file_get_contents when the path variable was assigned from $_GET nearby', async () => {
    const results = await scanCode(
      '<?php $path = $_GET["path"];\n$data = file_get_contents($path);', 'php'
    );
    expect(findByRule(results, 'CG-031').length).toBeGreaterThanOrEqual(1);
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

  it('detects a capitalized logger object and method (case-insensitive match)', async () => {
    const results = await scanCode('Logger.fatal("token=" + token)');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('does not mistake `new Error(...)` for a bare log call', async () => {
    // Regression guard: bare call names must stay case-sensitive.
    // Lowercasing `Error` collides with the `error` entry in LOG_FUNCTIONS.
    const results = await scanCode('new Error("password reset failed for " + token)');
    expect(findByRule(results, 'CG-040').length).toBe(0);
  });
});

describe('CG-040: Sensitive Data Exposure (Go)', () => {
  it('detects log.Printf logging a password', async () => {
    const source = `package main
func f(password string) {
	log.Printf("user password: %s", password)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('detects logrus.Info logging a token', async () => {
    const source = `package main
func f(token string) {
	logrus.Info("token=" + token)
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores logging non-sensitive data', async () => {
    const source = `package main
func f() {
	log.Println("server started")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-040').length).toBe(0);
  });
});

describe('CG-040: Sensitive Data Exposure (Java)', () => {
  it('detects logger.info logging a password', async () => {
    const source = `class T {
  void f(String password) {
    logger.info("password=" + password);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('detects System.out.println logging a secret', async () => {
    const source = `class T {
  void f(String secret) {
    System.out.println("secret: " + secret);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores logging non-sensitive data', async () => {
    const source = `class T {
  void f() {
    logger.info("server started");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-040').length).toBe(0);
  });
});

describe('CG-040: Sensitive Data Exposure (PHP)', () => {
  it('detects error_log logging a password', async () => {
    const results = await scanCode('<?php error_log("password=" . $password);', 'php');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it("detects Log::error (Laravel-style facade) logging a token", async () => {
    const results = await scanCode('<?php Log::error("token=" . $token);', 'php');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('detects $logger->info logging a secret', async () => {
    const results = await scanCode('<?php $logger->info("secret: " . $secret);', 'php');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores logging non-sensitive data', async () => {
    const results = await scanCode('<?php $logger->info("server started");', 'php');
    expect(findByRule(results, 'CG-040').length).toBe(0);
  });

  it('detects a differently-cased bare error_log call (PHP function names are case-insensitive)', async () => {
    const results = await scanCode('<?php Error_Log("password=" . $password);', 'php');
    expect(findByRule(results, 'CG-040').length).toBeGreaterThanOrEqual(1);
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

describe('CG-041: Insecure Deserialization (Java)', () => {
  it('detects ObjectInputStream#readObject', async () => {
    const source = `class T {
  Object f(ObjectInputStream ois) throws Exception {
    return ois.readObject();
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-041').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores unrelated method calls', async () => {
    const source = `class T {
  String f(String s) {
    return s.trim();
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-041').length).toBe(0);
  });
});

describe('CG-041: Insecure Deserialization (PHP)', () => {
  it('detects bare unserialize()', async () => {
    const results = await scanCode('<?php $obj = unserialize($data);', 'php');
    expect(findByRule(results, 'CG-041').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores unrelated function calls', async () => {
    const results = await scanCode('<?php $s = trim($data);', 'php');
    expect(findByRule(results, 'CG-041').length).toBe(0);
  });

  it('ignores a method named unserialize() on an object (Serializable interface)', async () => {
    // Regression guard: PHP's dangerous global unserialize() takes no
    // receiver. A class implementing the standard Serializable interface
    // defines its own unserialize() method, which is an unrelated, benign
    // pattern that happens to share the name.
    const results = await scanCode('<?php $session->unserialize($data);', 'php');
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

describe('CG-050: Security Misconfiguration (Go)', () => {
  it('detects InsecureSkipVerify: true', async () => {
    const source = `package main
func f() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a secure TLS config', async () => {
    const source = `package main
func f() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-050').length).toBe(0);
  });
});

describe('CG-050: Security Misconfiguration (Java)', () => {
  it('detects Spring csrf().disable()', async () => {
    const source = `class T {
  void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('detects Spring CORS wildcard allowedOrigins', async () => {
    const source = `class T {
  void configure(CorsRegistry registry) {
    registry.addMapping("/**").allowedOrigins("*");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('detects setSecure(false) on a cookie', async () => {
    const source = `class T {
  void f(Cookie cookie) {
    cookie.setSecure(false);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a securely configured cookie', async () => {
    const source = `class T {
  void f(Cookie cookie) {
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-050').length).toBe(0);
  });
});

describe('CG-050: Security Misconfiguration (PHP)', () => {
  it('detects CURLOPT_SSL_VERIFYPEER disabled', async () => {
    const results = await scanCode(
      '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);', 'php'
    );
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it("detects ini_set('display_errors', 1)", async () => {
    const results = await scanCode("<?php ini_set('display_errors', 1);", 'php');
    expect(findByRule(results, 'CG-050').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores CURLOPT_SSL_VERIFYPEER enabled', async () => {
    const results = await scanCode(
      '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);', 'php'
    );
    expect(findByRule(results, 'CG-050').length).toBe(0);
  });
});

// ── CG-023: Insecure Regular Expression (ReDoS) ─────────────────

describe('CG-023: Insecure Regular Expression (ReDoS)', () => {
  it('detects new RegExp with a nested quantifier', async () => {
    const results = await scanCode('new RegExp("(a+)+")');
    expect(findByRule(results, 'CG-023').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores new RegExp with a benign pattern', async () => {
    const results = await scanCode('new RegExp("a+b")');
    expect(findByRule(results, 'CG-023').length).toBe(0);
  });
});

describe('CG-023: Insecure Regular Expression (ReDoS) (Python)', () => {
  it("detects re.compile with a nested quantifier", async () => {
    const results = await scanCode('re.compile(r"(a+)+")', 'python');
    expect(findByRule(results, 'CG-023').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores an unrelated .split() call (not the re module)', async () => {
    const results = await scanCode('s.split(",")', 'python');
    expect(findByRule(results, 'CG-023').length).toBe(0);
  });
});

describe('CG-023: Insecure Regular Expression (ReDoS) (Go)', () => {
  it('detects regexp.MustCompile with a nested quantifier', async () => {
    const source = `package main
func f() {
	regexp.MustCompile("(a+)+")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-023').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores regexp.MustCompile with a benign pattern', async () => {
    const source = `package main
func f() {
	regexp.MustCompile("a+b")
}`;
    const results = await scanCode(source, 'go');
    expect(findByRule(results, 'CG-023').length).toBe(0);
  });
});

describe('CG-023: Insecure Regular Expression (ReDoS) (Java)', () => {
  it('detects Pattern.compile with a nested quantifier', async () => {
    const source = `class T {
  void f() {
    Pattern.compile("(a+)+");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-023').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores Pattern.compile with a benign pattern', async () => {
    const source = `class T {
  void f() {
    Pattern.compile("a+b");
  }
}`;
    const results = await scanCode(source, 'java');
    expect(findByRule(results, 'CG-023').length).toBe(0);
  });
});

describe('CG-023: Insecure Regular Expression (ReDoS) (PHP)', () => {
  it('detects preg_match with a nested quantifier', async () => {
    const results = await scanCode('<?php preg_match("/(a+)+/", $s);', 'php');
    expect(findByRule(results, 'CG-023').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores preg_match with a benign pattern', async () => {
    const results = await scanCode('<?php preg_match("/a+b/", $s);', 'php');
    expect(findByRule(results, 'CG-023').length).toBe(0);
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

// ── PHP MVP rules: CG-001 / CG-002 / CG-003 / CG-020 / CG-030 / CG-060 ──

describe('CG-001: SQL Injection (PHP)', () => {
  it('detects bare mysqli_query with concatenation', async () => {
    const source = '<?php function f($conn, $id) { return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects PDO->query with an interpolated string', async () => {
    const source = '<?php function f($pdo, $id) { return $pdo->query("SELECT * FROM orders WHERE id = $id"); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('detects a Laravel-style DB::query static facade call', async () => {
    const source = '<?php $rows = DB::query("SELECT * FROM users WHERE id = " . $id); ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-001').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores PDO prepare/execute placeholder usage', async () => {
    const source = `<?php
function f($pdo, $id) {
  $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
  $stmt->execute([$id]);
  return $stmt->fetchAll();
}
?>`;
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-001').length).toBe(0);
  });

  it('ignores unrelated function calls', async () => {
    const source = '<?php echo query("hello " . $name); ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-001').length).toBe(0);
  });
});

describe('CG-002: Command Injection (PHP)', () => {
  it('detects exec with concatenation', async () => {
    const source = '<?php function f($dir) { exec("ls -la " . $dir); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('detects shell_exec with concatenation', async () => {
    const source = '<?php function f($path) { shell_exec("cat " . $path); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static commands', async () => {
    const source = '<?php exec("ls -la", $output); ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBe(0);
  });

  it('detects system with concatenation', async () => {
    const source = '<?php function f($dir) { system("ls -la " . $dir); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('detects popen with concatenation', async () => {
    const source = '<?php function f($dir) { popen("ls -la " . $dir, "r"); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores a call to an unrelated bare function named like a Python subprocess helper', async () => {
    // Regression guard: isPyCmd must not match PHP just because a bare
    // function CALL happens to share a name with Python's subprocess API.
    const source = '<?php function build($target) { return run("building " . $target); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-002').length).toBe(0);
  });
});

describe('CG-003: Code Injection (PHP)', () => {
  it('detects eval with user input', async () => {
    const source = '<?php function f($code) { eval($code); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-003').length).toBeGreaterThanOrEqual(1);
  });
});

describe('CG-020: Hardcoded Credentials (PHP)', () => {
  it('detects a literal password assignment', async () => {
    const source = '<?php $password = "SuperSecret123!"; ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-020').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores credentials read from the environment', async () => {
    const source = '<?php $password = getenv("DB_PASSWORD"); ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-020').length).toBe(0);
  });
});

describe('CG-030: Path Traversal (PHP)', () => {
  it('detects file_get_contents with concatenated path', async () => {
    const source = '<?php function f($name) { return file_get_contents("/uploads/" . $name); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-030').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static paths', async () => {
    const source = '<?php function f() { return file_get_contents("/etc/app/config.yml"); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-030').length).toBe(0);
  });
});

describe('CG-060: SSRF (PHP)', () => {
  it('detects curl_init with concatenated URL', async () => {
    const source = '<?php function f($host) { return curl_init("http://" . $host . "/avatar.png"); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-060').length).toBeGreaterThanOrEqual(1);
  });

  it('ignores static URLs', async () => {
    const source = '<?php function f() { return curl_init("https://status.example.com/health"); } ?>';
    const results = await scanCode(source, 'php');
    expect(findByRule(results, 'CG-060').length).toBe(0);
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
