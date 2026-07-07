import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { scan } from '../../src/scanner/orchestrator.js';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';
import { VERSION } from '../../src/version.js';
import type { AnalyzeFindingsDependencies } from '../../src/analyzer/index.js';
import type { ScanOptions } from '../../src/scanner/orchestrator.js';
import type { LLMConfig } from '../../src/types/index.js';

const FIXTURES_DIR = resolve(__dirname, '../fixtures');
const VULNERABLE_INJECTION_FILE = resolve(FIXTURES_DIR, 'vulnerable', 'injection.ts');

function makeOptions(paths: string[], overrides: Partial<ScanOptions> = {}): ScanOptions {
  return {
    paths,
    config: DEFAULT_CONFIG,
    fix: false,
    dryRun: true,
    output: 'json',
    verbose: false,
    ...overrides,
  };
}

function makeLLMConfig(overrides: Partial<LLMConfig> = {}): LLMConfig {
  return {
    ...DEFAULT_CONFIG.llm,
    apiKey: 'test-key',
    ...overrides,
  };
}

function makeDependencies(
  responseText: string,
  usage: { inputTokens: number; outputTokens: number } = { inputTokens: 1000, outputTokens: 200 },
): AnalyzeFindingsDependencies {
  const provider = async () => ({
    text: responseText,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
  });

  return {
    providers: {
      claude: provider,
      openai: provider,
    },
  };
}

async function runMuted<T>(fn: () => Promise<T>): Promise<T> {
  const originalWrite = process.stdout.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await fn();
  } finally {
    process.stdout.write = originalWrite;
  }
}

async function withTempDir<T>(fn: (tempDir: string) => Promise<T>): Promise<T> {
  const tempDir = await mkdtemp(resolve(FIXTURES_DIR, 'tmp-scanner-custom-'));

  try {
    return await fn(tempDir);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

describe('Scanner orchestrator', () => {
  it('finds vulnerabilities in vulnerable fixtures', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')]);
    const result = await runMuted(() => scan(options));
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.files).toBeGreaterThan(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(result.llmCalls).toBe(0);
    expect(result.estimatedCost).toBe(0);
  });

  it('finds zero vulnerabilities in safe fixtures', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'safe')]);
    const result = await runMuted(() => scan(options));
    expect(result.findings.length).toBe(0);
  });

  it('honors inline codeguard-ignore directives end-to-end and counts them', async () => {
    await withTempDir(async tempDir => {
      const file = resolve(tempDir, 'sample.js');
      await writeFile(file, [
        'pool.query(`SELECT * FROM users WHERE id = ${a}`);',
        'pool.query(`SELECT * FROM users WHERE id = ${b}`); // codeguard-ignore',
        '// codeguard-ignore-next-line CG-001',
        'pool.query(`SELECT * FROM users WHERE id = ${c}`);',
      ].join('\n'));

      const result = await runMuted(() => scan(makeOptions([file])));
      // Only the first (unsuppressed) query survives; two were silenced.
      expect(result.findings.filter(f => f.ruleId === 'CG-001')).toHaveLength(1);
      expect(result.suppressed).toBe(2);
    });
  });

  it('absorbs baselined findings and reports only new ones, surviving line shifts', async () => {
    await withTempDir(async tempDir => {
      const file = resolve(tempDir, 'app.js');
      const baselinePath = resolve(tempDir, 'baseline.json');
      await writeFile(file, [
        'pool.query(`SELECT * FROM users WHERE id = ${a}`);',
        'res.redirect(req.query.next);',
      ].join('\n'));

      // Snapshot the current findings.
      const first = await runMuted(() => scan(makeOptions([file])));
      expect(first.findings.length).toBe(2);
      const { writeBaseline } = await import('../../src/scanner/baseline.js');
      await writeBaseline(first.findings, baselinePath);

      // Shift everything down and add one genuinely new vulnerability.
      await writeFile(file, [
        '// pushed down by new comments',
        '',
        'pool.query(`SELECT * FROM users WHERE id = ${a}`);',
        'res.redirect(req.query.next);',
        'eval(userInput);',
      ].join('\n'));

      const second = await runMuted(() => scan(makeOptions([file], { baselinePath })));
      expect(second.baselined).toBe(2);
      expect(second.findings).toHaveLength(1);
      expect(second.findings[0].ruleId).toBe('CG-003');
    });
  });

  it('reports suppressed findings again when inlineSuppression is disabled', async () => {
    await withTempDir(async tempDir => {
      const file = resolve(tempDir, 'sample.js');
      await writeFile(file, [
        'pool.query(`SELECT * FROM users WHERE id = ${a}`);',
        'pool.query(`SELECT * FROM users WHERE id = ${b}`); // codeguard-ignore',
      ].join('\n'));

      const result = await runMuted(() => scan(makeOptions([file], { inlineSuppression: false })));
      expect(result.findings.filter(f => f.ruleId === 'CG-001')).toHaveLength(2);
      expect(result.suppressed).toBe(0);
    });
  });

  it('rejects an invalid minSeverity instead of silently filtering everything', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')], {
      minSeverity: 'hgih' as never,
    });
    await expect(runMuted(() => scan(options))).rejects.toThrow(/Invalid severity/);
  });

  it('generates findings with sequential IDs', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')]);
    const result = await runMuted(() => scan(options));
    for (let i = 0; i < result.findings.length; i++) {
      expect(result.findings[i].id).toBe(`finding-${i + 1}`);
    }
  });

  it('includes severity from rule definition', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')]);
    const result = await runMuted(() => scan(options));
    for (const finding of result.findings) {
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
    }
  });

  it('uses relative file paths in findings', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')]);
    const result = await runMuted(() => scan(options));
    for (const finding of result.findings) {
      expect(finding.file).not.toMatch(/^[A-Z]:\\/);
      expect(finding.file).toContain('tests/fixtures/vulnerable');
    }
  });

  it('writes report to file when outputFile specified', async () => {
    const fs = await import('node:fs/promises');
    const outputFile = resolve(FIXTURES_DIR, '../tmp-test-report.json');
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')], {
      outputFile,
      output: 'json',
    });

    try {
      await scan(options);
      const content = await fs.readFile(outputFile, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed.version).toBe(VERSION);
      expect(parsed.findings.length).toBeGreaterThan(0);
    } finally {
      await fs.unlink(outputFile).catch(() => {});
    }
  });

  it('skips unsupported file extensions', async () => {
    const options = makeOptions(['nonexistent.css']);
    const result = await runMuted(() => scan(options));
    expect(result.files).toBe(0);
    expect(result.findings.length).toBe(0);
  });

  it('outputs SARIF format', async () => {
    const options = makeOptions([resolve(FIXTURES_DIR, 'vulnerable')], {
      output: 'sarif',
    });
    const originalWrite = process.stdout.write;
    let captured = '';
    process.stdout.write = ((chunk: string) => { captured += chunk; return true; }) as typeof process.stdout.write;
    try {
      await scan(options);
      const sarif = JSON.parse(captured);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
    } finally {
      process.stdout.write = originalWrite;
    }
  });

  it('finds custom rule findings in final results', async () => {
    await withTempDir(async tempDir => {
      const sourceFile = resolve(tempDir, 'custom-target.ts');
      const ruleFile = resolve(tempDir, 'custom-rule.yml');

      await writeFile(sourceFile, 'customExec(userInput);\n');
      await writeFile(ruleFile, `id: CR-200
name: Custom exec detector
severity: high
category: injection
languages:
  - typescript
description: Detects customExec calls
patterns:
  - type: function_call
    function:
      match:
        - customExec
`);

      const options = makeOptions([sourceFile], {
        config: {
          ...DEFAULT_CONFIG,
          rules: {
            preset: 'none',
            custom: ruleFile,
            disable: [],
          },
        },
      });

      const result = await runMuted(() => scan(options));

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].ruleId).toBe('CR-200');
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].file).toContain('tests/fixtures/tmp-scanner-custom-');
      expect(result.findings[0].file).toMatch(/\/custom-target\.ts$/);
    });
  });

  it('runs Stage 2 analysis when dryRun is false', async () => {
    const options = makeOptions([VULNERABLE_INJECTION_FILE], {
      dryRun: false,
      config: {
        ...DEFAULT_CONFIG,
        llm: makeLLMConfig(),
      },
    });

    const result = await runMuted(() => scan(
      options,
      makeDependencies(JSON.stringify({
        confirmed: true,
        confidence: 0.92,
        reasoning: 'Untrusted input reaches a dangerous sink.',
      })),
    ));

    expect(result.suspicious).toBeGreaterThan(0);
    expect(result.llmCalls).toBe(result.suspicious);
    expect(result.estimatedCost).toBeGreaterThan(0);
    expect(result.findings.length).toBe(result.suspicious);
    for (const finding of result.findings) {
      expect(finding.llmAnalysis?.confirmed).toBe(true);
    }
  });

  it('adds fix suggestions when fix is enabled', async () => {
    const options = makeOptions([VULNERABLE_INJECTION_FILE], {
      dryRun: false,
      fix: true,
      config: {
        ...DEFAULT_CONFIG,
        llm: makeLLMConfig(),
      },
    });

    const result = await runMuted(() => scan(
      options,
      makeDependencies(JSON.stringify({
        confirmed: true,
        confidence: 0.95,
        reasoning: 'The query is constructed from user input.',
        fixDescription: 'Use parameterized queries.',
        fixCode: 'pool.query("SELECT * FROM users WHERE id = $1", [userId])',
      })),
    ));

    expect(result.findings.some(finding => finding.fix)).toBe(true);
  });

  it('throws when Stage 2 runs without an API key', async () => {
    const options = makeOptions([VULNERABLE_INJECTION_FILE], {
      dryRun: false,
      config: {
        ...DEFAULT_CONFIG,
        llm: {
          ...DEFAULT_CONFIG.llm,
          apiKey: undefined,
        },
      },
    });

    await expect(runMuted(() => scan(options))).rejects.toThrow(
      'LLM API key is required for Stage 2 analysis',
    );
  });
});
