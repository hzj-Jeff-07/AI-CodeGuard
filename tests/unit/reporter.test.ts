import { describe, it, expect } from 'vitest';
import { formatJSON } from '../../src/reporter/json.js';
import { formatSARIF } from '../../src/reporter/sarif.js';
import { formatText } from '../../src/reporter/text.js';
import { VERSION } from '../../src/version.js';
import type { ScanResult, Finding } from '../../src/types/index.js';

function makeScanResult(findings: Finding[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    files: 3,
    suspicious: findings.length,
    findings,
    skipped: [],
    duration: 1234,
    llmCalls: 0,
    estimatedCost: 0,
    cacheHits: 0,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    ruleId: 'CG-001',
    severity: 'critical',
    title: 'SQL Injection',
    description: 'Potential SQL Injection detected.',
    file: 'src/db.ts',
    location: {
      start: { line: 10, column: 0 },
      end: { line: 10, column: 50 },
    },
    snippet: 'pool.query(`SELECT * FROM users WHERE id = ${id}`)',
    ...overrides,
  };
}

// ── formatJSON ──────────────────────────────────────────────────

describe('formatJSON', () => {
  it('returns valid JSON', () => {
    const result = makeScanResult([makeFinding()]);
    const output = formatJSON(result);
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes version field', () => {
    const result = makeScanResult();
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.version).toBe(VERSION);
  });

  it('includes scan metadata', () => {
    const result = makeScanResult([makeFinding()]);
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.scan.files).toBe(3);
    expect(parsed.scan.suspicious).toBe(1);
    expect(parsed.scan.duration).toBe(1234);
  });

  it('includes dismissed findings with their reasoning', () => {
    const dismissed = makeFinding({
      description: 'Potential SQL Injection detected. Dismissed by Stage 2 analysis.',
      llmAnalysis: { confirmed: false, confidence: 0.2, reasoning: 'Parameterized query.' },
    });
    const result = makeScanResult([], { llmCalls: 1, dismissedFindings: [dismissed] });
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.dismissedFindings).toHaveLength(1);
    expect(parsed.dismissedFindings[0].llmAnalysis.confirmed).toBe(false);
    expect(parsed.dismissedFindings[0].llmAnalysis.reasoning).toBe('Parameterized query.');
  });

  it('includes findings array', () => {
    const finding = makeFinding();
    const result = makeScanResult([finding]);
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe('CG-001');
    expect(parsed.findings[0].severity).toBe('critical');
    expect(parsed.findings[0].file).toBe('src/db.ts');
  });

  it('handles empty findings', () => {
    const result = makeScanResult();
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.findings).toHaveLength(0);
  });

  it('includes fix when present', () => {
    const finding = makeFinding({
      fix: { description: 'Use parameterized query', code: 'db.query("SELECT ?", [id])' },
    });
    const result = makeScanResult([finding]);
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.findings[0].fix).not.toBeNull();
    expect(parsed.findings[0].fix.description).toBe('Use parameterized query');
  });

  it('sets fix to null when absent', () => {
    const result = makeScanResult([makeFinding()]);
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.findings[0].fix).toBeNull();
  });

  it('includes llmAnalysis when present', () => {
    const finding = makeFinding({
      llmAnalysis: {
        confirmed: true,
        confidence: 0.92,
        reasoning: 'User input reaches a dangerous query sink.',
      },
    });
    const result = makeScanResult([finding], { llmCalls: 1, estimatedCost: 0.123456 });
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.scan.llmCalls).toBe(1);
    expect(parsed.scan.estimatedCost).toBe(0.123456);
    expect(parsed.findings[0].llmAnalysis).not.toBeNull();
    expect(parsed.findings[0].llmAnalysis.reasoning).toContain('dangerous query sink');
  });

  it('includes skipped files', () => {
    const result = makeScanResult([], {
      skipped: [{ file: 'style.css', reason: 'Unsupported language' }],
    });
    const parsed = JSON.parse(formatJSON(result));
    expect(parsed.skipped).toHaveLength(1);
    expect(parsed.skipped[0].file).toBe('style.css');
  });
});

// ── formatSARIF ─────────────────────────────────────────────────

describe('formatSARIF', () => {
  it('returns valid JSON', () => {
    const result = makeScanResult([makeFinding()]);
    expect(() => JSON.parse(formatSARIF(result))).not.toThrow();
  });

  it('has correct SARIF schema and version', () => {
    const result = makeScanResult([makeFinding()]);
    const sarif = JSON.parse(formatSARIF(result));
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
  });

  it('has tool driver info', () => {
    const result = makeScanResult([makeFinding()]);
    const sarif = JSON.parse(formatSARIF(result));
    expect(sarif.runs[0].tool.driver.name).toBe('AI-CodeGuard');
    expect(sarif.runs[0].tool.driver.version).toBe(VERSION);
  });

  it('maps severity to SARIF level correctly', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical', ruleId: 'CG-001' }),
      makeFinding({ id: 'f2', severity: 'high', ruleId: 'CG-010' }),
      makeFinding({ id: 'f3', severity: 'medium', ruleId: 'CG-050' }),
    ];
    const sarif = JSON.parse(formatSARIF(makeScanResult(findings)));
    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[1].level).toBe('error');
    expect(sarif.runs[0].results[2].level).toBe('warning');
  });

  it('includes location information', () => {
    const result = makeScanResult([makeFinding()]);
    const sarif = JSON.parse(formatSARIF(result));
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.region.startLine).toBe(10);
    expect(loc.artifactLocation.uri).toBe('src/db.ts');
  });

  it('includes rules in driver', () => {
    const result = makeScanResult([makeFinding()]);
    const sarif = JSON.parse(formatSARIF(result));
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThanOrEqual(1);
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe('CG-001');
  });

  it('handles empty findings', () => {
    const sarif = JSON.parse(formatSARIF(makeScanResult()));
    expect(sarif.runs[0].results).toHaveLength(0);
  });

  it('includes fix when present', () => {
    const finding = makeFinding({
      fix: { description: 'Use parameterized query', code: 'db.query("SELECT ?", [id])' },
    });
    const sarif = JSON.parse(formatSARIF(makeScanResult([finding])));
    expect(sarif.runs[0].results[0].fixes).toBeDefined();
    expect(sarif.runs[0].results[0].fixes[0].description.text).toBe('Use parameterized query');
  });

  it('includes llmAnalysis markdown when present', () => {
    const finding = makeFinding({
      llmAnalysis: {
        confirmed: true,
        confidence: 0.87,
        reasoning: 'The sink is reachable from untrusted input.',
      },
    });
    const sarif = JSON.parse(formatSARIF(makeScanResult([finding])));
    expect(sarif.runs[0].results[0].message.markdown).toContain('LLM Confidence: 87%');
    expect(sarif.runs[0].results[0].message.markdown).toContain('reachable from untrusted input');
  });
});

// ── formatText ──────────────────────────────────────────────────

describe('formatText', () => {
  it('shows "No vulnerabilities found" for empty results', () => {
    const output = formatText(makeScanResult());
    expect(output).toContain('No vulnerabilities found');
  });

  it('includes finding title and rule ID', () => {
    const output = formatText(makeScanResult([makeFinding()]));
    expect(output).toContain('SQL Injection');
    expect(output).toContain('CG-001');
  });

  it('includes file location', () => {
    const output = formatText(makeScanResult([makeFinding()]));
    expect(output).toContain('src/db.ts');
  });

  it('includes code snippet', () => {
    const output = formatText(makeScanResult([makeFinding()]));
    expect(output).toContain('pool.query');
  });

  it('includes summary with counts', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical' }),
      makeFinding({ id: 'f2', severity: 'high' }),
    ];
    const output = formatText(makeScanResult(findings));
    expect(output).toContain('2 findings');
    expect(output).toContain('1 critical');
    expect(output).toContain('1 high');
  });

  it('includes duration in summary', () => {
    const output = formatText(makeScanResult([], { duration: 2500 }));
    expect(output).toContain('2.5s');
  });

  it('shows dismissed count in summary when Stage 2 dismissed findings', () => {
    const dismissed = makeFinding({
      llmAnalysis: { confirmed: false, confidence: 0.2, reasoning: 'Not exploitable.' },
    });
    const output = formatText(makeScanResult([], { llmCalls: 1, dismissedFindings: [dismissed] }));
    expect(output).toContain('Dismissed by Stage 2: 1');
  });

  it('omits dismissed line when nothing was dismissed', () => {
    const output = formatText(makeScanResult([makeFinding()]));
    expect(output).not.toContain('Dismissed by Stage 2');
  });

  it('includes file count in summary', () => {
    const output = formatText(makeScanResult([], { files: 10 }));
    expect(output).toContain('10');
  });

  it('includes llmAnalysis in text output', () => {
    const finding = makeFinding({
      llmAnalysis: {
        confirmed: true,
        confidence: 0.91,
        reasoning: 'Untrusted data flows into the SQL sink.',
      },
    });
    const output = formatText(makeScanResult([finding], { llmCalls: 1, estimatedCost: 0.12 }));
    expect(output).toContain('LLM Confidence: 91%');
    expect(output).toContain('Untrusted data flows into the SQL sink.');
    expect(output).toContain('LLM calls: 1');
    expect(output).toContain('Estimated cost: $0.12');
  });
});
