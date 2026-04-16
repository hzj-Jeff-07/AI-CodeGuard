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
    expect(rules.length).toBe(13);
  });

  it('returns empty array for preset none', () => {
    const rules = getRules({ preset: 'none' });
    expect(rules).toEqual([]);
  });

  it('returns all rules for preset owasp-top-10', () => {
    const rules = getRules({ preset: 'owasp-top-10' });
    expect(rules.length).toBe(13);
  });

  it('returns all rules for preset all', () => {
    const rules = getRules({ preset: 'all' });
    expect(rules.length).toBe(13);
  });

  it('disables specified rules', () => {
    const rules = getRules({ disable: ['CG-001', 'CG-010'] });
    expect(rules.find(r => r.id === 'CG-001')).toBeUndefined();
    expect(rules.find(r => r.id === 'CG-010')).toBeUndefined();
    expect(rules.length).toBe(11);
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

// ── getAllRuleIds / getRuleById ──────────────────────────────────

describe('getAllRuleIds', () => {
  it('returns all 13 rule IDs', () => {
    const ids = getAllRuleIds();
    expect(ids.length).toBe(13);
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
