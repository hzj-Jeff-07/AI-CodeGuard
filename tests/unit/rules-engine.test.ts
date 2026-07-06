import { describe, it, expect } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRuleContext } from '../../src/rules/engine.js';
import { getRules, loadRules, runRules, getAllRuleIds, getRuleById } from '../../src/rules/index.js';
import { parse } from '../../src/parser/index.js';

const FIXTURES_DIR = resolve(__dirname, '../fixtures');

function makeCustomRuleYaml(options: {
  id: string;
  functionName: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  languages?: string[];
}): string {
  const {
    id,
    functionName,
    severity = 'high',
    languages = ['typescript'],
  } = options;

  return `id: ${id}
name: ${id} rule
severity: ${severity}
category: injection
languages:
${languages.map(language => `  - ${language}`).join('\n')}
description: Detects ${functionName} calls
patterns:
  - type: function_call
    function:
      match:
        - ${functionName}
`;
}

async function withTempDir<T>(fn: (tempDir: string) => Promise<T>): Promise<T> {
  const tempDir = await mkdtemp(resolve(FIXTURES_DIR, 'tmp-custom-rules-'));

  try {
    return await fn(tempDir);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

// ── createRuleContext ───────────────────────────────────────────

describe('createRuleContext', () => {
  const source = 'line1\nline2\nline3\nline4\nline5';
  const ctx = createRuleContext('test.ts', 'typescript', source);

  it('has correct file and language', () => {
    expect(ctx.file).toBe('test.ts');
    expect(ctx.language).toBe('typescript');
  });

  it('getSnippet returns node text', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call_expression',
      text: 'foo()',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 5 } },
      children: [],
      parent: null,
      fields: {},
    };
    expect(ctx.getSnippet(node)).toBe('foo()');
  });

  it('getContext returns surrounding lines', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call_expression',
      text: 'line3',
      location: { start: { line: 3, column: 0 }, end: { line: 3, column: 5 } },
      children: [],
      parent: null,
      fields: {},
    };
    const context = ctx.getContext(node, 1);
    expect(context).toContain('line2');
    expect(context).toContain('line3');
    expect(context).toContain('line4');
  });

  it('extractCallInfo delegates to adapter', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call_expression',
      text: 'db.query("SELECT 1")',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 20 } },
      children: [],
      parent: null,
      fields: {},
    };
    const info = ctx.extractCallInfo(node);
    expect(info).not.toBeNull();
    expect(info!.name).toBe('query');
    expect(info!.object).toBe('db');
  });
});

// ── getRules ────────────────────────────────────────────────────

describe('getRules', () => {
  it('returns all rules with default options', () => {
    const rules = getRules();
    expect(rules.length).toBe(19);
  });

  it('returns empty array for preset none', () => {
    const rules = getRules({ preset: 'none' });
    expect(rules).toEqual([]);
  });

  it('returns all rules for preset owasp-top-10', () => {
    const rules = getRules({ preset: 'owasp-top-10' });
    expect(rules.length).toBe(19);
  });

  it('returns all rules for preset all', () => {
    const rules = getRules({ preset: 'all' });
    expect(rules.length).toBe(19);
  });

  it('disables specified rules', () => {
    const rules = getRules({ disable: ['CG-001', 'CG-010'] });
    expect(rules.find(r => r.id === 'CG-001')).toBeUndefined();
    expect(rules.find(r => r.id === 'CG-010')).toBeUndefined();
    expect(rules.length).toBe(17);
  });
});

// ── loadRules ───────────────────────────────────────────────────

describe('loadRules', () => {
  it('loads custom rules from a YAML file with preset none', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'custom.yml');
      await writeFile(ruleFile, makeCustomRuleYaml({ id: 'CR-100', functionName: 'customExec' }));

      const rules = await loadRules({ preset: 'none', custom: ruleFile });

      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('CR-100');
    });
  });

  it('loads custom rules recursively from a directory', async () => {
    await withTempDir(async tempDir => {
      const nestedDir = resolve(tempDir, 'nested');
      await mkdir(nestedDir, { recursive: true });
      await writeFile(resolve(tempDir, 'first.yml'), makeCustomRuleYaml({ id: 'CR-101', functionName: 'firstSink' }));
      await writeFile(resolve(nestedDir, 'second.yaml'), makeCustomRuleYaml({ id: 'CR-102', functionName: 'secondSink' }));

      const rules = await loadRules({ preset: 'none', custom: tempDir });
      const ids = rules.map(rule => rule.id);

      expect(rules).toHaveLength(2);
      expect(ids).toEqual(expect.arrayContaining(['CR-101', 'CR-102']));
    });
  });

  it('applies disable filters to built-in and custom rules', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'custom.yml');
      await writeFile(ruleFile, makeCustomRuleYaml({ id: 'CR-103', functionName: 'customExec' }));

      const rules = await loadRules({
        custom: ruleFile,
        disable: ['CG-001', 'CR-103'],
      });

      expect(rules.some(rule => rule.id === 'CG-001')).toBe(false);
      expect(rules.some(rule => rule.id === 'CR-103')).toBe(false);
      expect(rules.some(rule => rule.id === 'CG-002')).toBe(true);
    });
  });

  it('throws for invalid YAML custom rule files', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'invalid.yml');
      await writeFile(ruleFile, 'rules: [');

      await expect(loadRules({ preset: 'none', custom: ruleFile })).rejects.toThrow(
        'Failed to parse custom rules file',
      );
    });
  });

  it('throws for invalid custom rule schema', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'invalid-schema.yml');
      await writeFile(ruleFile, `id: CR-104
name: Invalid rule
severity: severe
category: injection
languages:
  - typescript
description: Invalid severity should fail
patterns:
  - type: function_call
`);

      await expect(loadRules({ preset: 'none', custom: ruleFile })).rejects.toThrow(
        'Invalid custom rules',
      );
    });
  });

  it('throws for duplicate custom rule IDs', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'duplicate.yml');
      await writeFile(ruleFile, makeCustomRuleYaml({ id: 'CG-001', functionName: 'customExec' }));

      await expect(loadRules({ custom: ruleFile })).rejects.toThrow(
        'Duplicate custom rule ID "CG-001"',
      );
    });
  });
});

// ── custom rule pattern semantics ────────────────────────────────

describe('custom rule pattern semantics', () => {
  async function scanWithRule(ruleYaml: string, source: string, lang: 'typescript' | 'python' = 'typescript') {
    return withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'rule.yml');
      await writeFile(ruleFile, ruleYaml);
      const rules = await loadRules({ preset: 'none', custom: ruleFile });
      const tree = await parse(source, lang);
      return runRules(tree, rules, lang === 'python' ? 'test.py' : 'test.ts');
    });
  }

  const HEADER = `id: CR-200
name: semantics rule
severity: high
category: injection
languages: [typescript]
description: pattern semantics test
`;

  it('matches function.on receivers and rejects other objects', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [rawQuery]
      on: [db]
`;
    expect(await scanWithRule(rule, 'db.rawQuery("SELECT 1")')).toHaveLength(1);
    expect(await scanWithRule(rule, 'cache.rawQuery("SELECT 1")')).toHaveLength(0);
    expect(await scanWithRule(rule, 'rawQuery("SELECT 1")')).toHaveLength(0);
  });

  it('requires template_string arguments with expressions when specified', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [sink]
    arguments:
      - type: template_string
        hasExpressions: true
`;
    expect(await scanWithRule(rule, 'sink(`SELECT ${id}`)')).toHaveLength(1);
    expect(await scanWithRule(rule, 'sink(`SELECT 1`)')).toHaveLength(0);
    expect(await scanWithRule(rule, 'sink("SELECT 1")')).toHaveLength(0);
  });

  it('matches string_concat arguments with the + operator', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [sink]
    arguments:
      - type: string_concat
        operator: "+"
`;
    expect(await scanWithRule(rule, 'sink("a" + userInput)')).toHaveLength(1);
    expect(await scanWithRule(rule, 'sink("ab")')).toHaveLength(0);
  });

  it('suppresses matches via exclude patterns', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [render]
exclude:
  - type: function_call
    hasExpressions: false
`;
    expect(await scanWithRule(rule, 'render(`hello ${userInput}`)')).toHaveLength(1);
    expect(await scanWithRule(rule, 'render("static")')).toHaveLength(0);
  });

  it('treats multiple patterns as OR', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [dangerousA]
  - type: function_call
    function:
      match: [dangerousB]
`;
    expect(await scanWithRule(rule, 'dangerousA()')).toHaveLength(1);
    expect(await scanWithRule(rule, 'dangerousB()')).toHaveLength(1);
    expect(await scanWithRule(rule, 'safeCall()')).toHaveLength(0);
  });

  it('detects Python f-string interpolation via hasExpressions', async () => {
    const rule = `id: CR-201
name: python f-string rule
severity: high
category: injection
languages: [python]
description: f-string test
patterns:
  - type: function_call
    function:
      match: [sink]
    arguments:
      - type: template_string
        hasExpressions: true
`;
    expect(await scanWithRule(rule, 'sink(f"select {x}")', 'python')).toHaveLength(1);
    expect(await scanWithRule(rule, 'sink(f"static")', 'python')).toHaveLength(0);
  });

  it('tags custom findings with their source file in metadata', async () => {
    const rule = HEADER + `patterns:
  - type: function_call
    function:
      match: [rawQuery]
`;
    const results = await scanWithRule(rule, 'rawQuery("x")');
    expect(results).toHaveLength(1);
    expect(results[0].metadata.source).toBe('custom');
    expect(String(results[0].metadata.ruleSource)).toContain('rule.yml');
  });
});

// ── custom rule loader failure paths ─────────────────────────────

describe('custom rule loader failure paths', () => {
  it('throws for a nonexistent custom rules path', async () => {
    await expect(loadRules({ preset: 'none', custom: resolve(FIXTURES_DIR, 'does-not-exist.yml') }))
      .rejects.toThrow('Custom rules path not found');
  });

  it('throws for a directory without YAML files', async () => {
    await withTempDir(async tempDir => {
      await writeFile(resolve(tempDir, 'notes.txt'), 'not a rule');
      await expect(loadRules({ preset: 'none', custom: tempDir }))
        .rejects.toThrow('No YAML custom rule files found');
    });
  });

  it('throws for YAML that is not a rule shape (scalar document)', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'scalar.yml');
      await writeFile(ruleFile, 'just a string');
      await expect(loadRules({ preset: 'none', custom: ruleFile }))
        .rejects.toThrow('Invalid custom rules');
    });
  });

  it('throws for a pattern without any matcher', async () => {
    await withTempDir(async tempDir => {
      const ruleFile = resolve(tempDir, 'empty-pattern.yml');
      await writeFile(ruleFile, `id: CR-210
name: empty pattern
severity: high
category: injection
languages: [typescript]
description: pattern with no matcher
patterns:
  - {}
`);
      await expect(loadRules({ preset: 'none', custom: ruleFile }))
        .rejects.toThrow('Pattern must define at least one matcher');
    });
  });

  it('reports the first defining file for duplicate IDs across files', async () => {
    await withTempDir(async tempDir => {
      await writeFile(resolve(tempDir, 'a.yml'), makeCustomRuleYaml({ id: 'CR-300', functionName: 'sinkA' }));
      await writeFile(resolve(tempDir, 'b.yml'), makeCustomRuleYaml({ id: 'CR-300', functionName: 'sinkB' }));

      await expect(loadRules({ preset: 'none', custom: tempDir }))
        .rejects.toThrow(/Duplicate custom rule ID "CR-300".*already defined in.*a\.yml/);
    });
  });

  it('accepts both the rules-wrapper form and the top-level array form', async () => {
    await withTempDir(async tempDir => {
      await writeFile(resolve(tempDir, 'wrapper.yml'), `rules:
  - id: CR-301
    name: wrapped rule
    severity: high
    category: injection
    languages: [typescript]
    description: wrapper form
    patterns:
      - type: function_call
        function:
          match: [wrappedSink]
`);
      await writeFile(resolve(tempDir, 'array.yml'), `- id: CR-302
  name: array rule
  severity: high
  category: injection
  languages: [typescript]
  description: array form
  patterns:
    - type: function_call
      function:
        match: [arraySink]
`);

      const rules = await loadRules({ preset: 'none', custom: tempDir });
      expect(rules.map(rule => rule.id).sort()).toEqual(['CR-301', 'CR-302']);
    });
  });
});

// ── getAllRuleIds / getRuleById ──────────────────────────────────

describe('getAllRuleIds', () => {
  it('returns all 19 rule IDs', () => {
    const ids = getAllRuleIds();
    expect(ids.length).toBe(19);
    expect(ids).toContain('CG-001');
    expect(ids).toContain('CG-060');
  });
});

describe('getRuleById', () => {
  it('finds rule by ID', () => {
    const rule = getRuleById('CG-001');
    expect(rule).toBeDefined();
    expect(rule!.name).toBe('SQL Injection');
  });

  it('returns undefined for non-existent ID', () => {
    expect(getRuleById('CG-999')).toBeUndefined();
  });
});

// ── runRules ────────────────────────────────────────────────────

describe('runRules', () => {
  it('finds SQL injection in vulnerable code', async () => {
    const source = 'pool.query(`SELECT * FROM users WHERE id = ${userId}`)';
    const tree = await parse(source, 'typescript');
    const rules = getRules();
    const results = runRules(tree, rules, 'test.ts');
    const sqli = results.filter(r => r.ruleId === 'CG-001');
    expect(sqli.length).toBeGreaterThanOrEqual(1);
  });

  it('returns empty for safe code', async () => {
    const source = 'const x = 1 + 2;';
    const tree = await parse(source, 'typescript');
    const rules = getRules();
    const results = runRules(tree, rules, 'test.ts');
    expect(results.length).toBe(0);
  });

  it('deduplicates findings by location', async () => {
    const source = 'eval(userInput)';
    const tree = await parse(source, 'javascript');
    const rules = getRules();
    const results = runRules(tree, rules, 'test.js');
    const evalFindings = results.filter(r => r.ruleId === 'CG-003');
    const keys = evalFindings.map(r => `${r.ruleId}:${r.location.start.line}:${r.location.start.column}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('filters rules by language', async () => {
    const source = 'x = 1';
    const tree = await parse(source, 'python');
    const jsOnlyRules = getRules().filter(r =>
      r.languages.includes('javascript') && !r.languages.includes('python')
    );
    const results = runRules(tree, jsOnlyRules, 'test.py');
    expect(results.length).toBe(0);
  });
});

// ── runRules: nested same-rule duplicate suppression ─────────────
// Stage 1 has no dataflow, so a rule can independently flag both an outer
// call and a call nested inside it (e.g. Go/Java's SQL-injection rule also
// treats a SQL-assembling fmt.Sprintf/String.format as suspicious on its
// own, to catch the two-step `query := fmt.Sprintf(...); db.Query(query)`
// pattern). When that inner call is nested inline inside a matching outer
// call, both fire on overlapping spans for the same underlying issue.

describe('runRules nested-duplicate suppression', () => {
  it('collapses inline db.Query(fmt.Sprintf(...)) in Go to a single finding', async () => {
    const source = `package main
func f(id string) {
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	_ = rows
}`;
    const tree = await parse(source, 'go');
    const results = runRules(tree, getRules(), 'test.go');
    expect(results.filter(r => r.ruleId === 'CG-001')).toHaveLength(1);
  });

  it('collapses inline executeQuery(String.format(...)) in Java to a single finding', async () => {
    const source = `class T {
  ResultSet f(Statement stmt, String id) throws Exception {
    return stmt.executeQuery(String.format("SELECT * FROM users WHERE id = %s", id));
  }
}`;
    const tree = await parse(source, 'java');
    const results = runRules(tree, getRules(), 'test.java');
    expect(results.filter(r => r.ruleId === 'CG-001')).toHaveLength(1);
  });

  it('still reports the two-step Sprintf-then-Query pattern (not nested, not suppressed)', async () => {
    const source = `package main
func f(name string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	rows, _ := db.Query(query)
	_ = rows
}`;
    const tree = await parse(source, 'go');
    const results = runRules(tree, getRules(), 'test.go');
    expect(results.filter(r => r.ruleId === 'CG-001')).toHaveLength(1);
  });

  it('collapses a Go InsecureSkipVerify composite literal nested inside another literal', async () => {
    const source = `package main
func f() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}`;
    const tree = await parse(source, 'go');
    const results = runRules(tree, getRules(), 'test.go');
    expect(results.filter(r => r.ruleId === 'CG-050')).toHaveLength(1);
  });

  it('keeps two independent (non-nested) findings of the same rule', async () => {
    const source = `package main
func f() {
	md5.Sum([]byte("a"))
	sha1.New()
}`;
    const tree = await parse(source, 'go');
    const results = runRules(tree, getRules(), 'test.go');
    expect(results.filter(r => r.ruleId === 'CG-021')).toHaveLength(2);
  });
});
