import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import {
  assertWritableBaselinePath,
  buildBaseline,
  filterAgainstBaseline,
  fingerprintFinding,
  loadBaseline,
  writeBaseline,
} from '../../src/scanner/baseline.js';
import type { Finding } from '../../src/types/index.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    ruleId: 'CG-001',
    severity: 'critical',
    title: 'SQL Injection',
    description: 'desc',
    file: 'src/db.ts',
    location: { start: { line: 10, column: 0 }, end: { line: 10, column: 50 } },
    snippet: 'pool.query(`SELECT * FROM users WHERE id = ${id}`)',
    ...overrides,
  };
}

describe('fingerprintFinding', () => {
  it('is stable when the finding moves to a different line', () => {
    const moved = finding({ location: { start: { line: 99, column: 4 }, end: { line: 99, column: 54 } } });
    expect(fingerprintFinding(moved)).toBe(fingerprintFinding(finding()));
  });

  it('is stable across whitespace-only reformatting of the snippet', () => {
    const reformatted = finding({ snippet: 'pool.query(\n  `SELECT * FROM users WHERE id = ${id}`\n)'.replace('(\n  ', '( ').replace('\n)', ' )') });
    // Same tokens, different spacing.
    expect(fingerprintFinding(finding({ snippet: 'pool.query( `SELECT * FROM users WHERE id = ${id}` )' })))
      .toBe(fingerprintFinding(reformatted));
  });

  it('changes when the rule differs', () => {
    expect(fingerprintFinding(finding({ ruleId: 'CG-002' }))).not.toBe(fingerprintFinding(finding()));
  });

  it('changes when the file differs', () => {
    expect(fingerprintFinding(finding({ file: 'src/other.ts' }))).not.toBe(fingerprintFinding(finding()));
  });

  it('changes when the code itself differs', () => {
    expect(fingerprintFinding(finding({ snippet: 'pool.query(`SELECT * FROM t WHERE x = ${y}`)' })))
      .not.toBe(fingerprintFinding(finding()));
  });
});

describe('buildBaseline / filterAgainstBaseline', () => {
  it('absorbs findings covered by the baseline', () => {
    const baseline = buildBaseline([finding()]);
    const result = filterAgainstBaseline([finding()], baseline);
    expect(result.kept).toHaveLength(0);
    expect(result.baselined).toBe(1);
  });

  it('keeps findings not in the baseline', () => {
    const baseline = buildBaseline([finding()]);
    const newFinding = finding({ ruleId: 'CG-002', title: 'Command Injection' });
    const result = filterAgainstBaseline([finding(), newFinding], baseline);
    expect(result.kept).toHaveLength(1);
    expect(result.kept[0].ruleId).toBe('CG-002');
    expect(result.baselined).toBe(1);
  });

  it('counts duplicate fingerprints so extra copies surface as new', () => {
    // Two identical findings acknowledged; a third copy must still be reported.
    const baseline = buildBaseline([finding(), finding()]);
    const result = filterAgainstBaseline([finding(), finding(), finding()], baseline);
    expect(result.baselined).toBe(2);
    expect(result.kept).toHaveLength(1);
  });
});

describe('writeBaseline / loadBaseline', () => {
  it('round-trips through disk', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'baseline.json');
      await writeBaseline([finding()], path);
      const loaded = await loadBaseline(path);
      expect(loaded.version).toBe(1);
      expect(loaded.fingerprints[fingerprintFinding(finding())]).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('fails clearly for a missing file', async () => {
    await expect(loadBaseline('/nonexistent/baseline.json')).rejects.toThrow(/Baseline file not found/);
  });

  it('fails clearly for invalid JSON', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'broken.json');
      await writeFile(path, '{ not json');
      await expect(loadBaseline(path)).rejects.toThrow(/not valid JSON/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('fails clearly for an unsupported version', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'future.json');
      await writeFile(path, JSON.stringify({ version: 999, fingerprints: {} }));
      await expect(loadBaseline(path)).rejects.toThrow(/Unsupported baseline format/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects non-integer fingerprint counts', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'bad-counts.json');
      await writeFile(path, JSON.stringify({ version: 1, fingerprints: { abcd: 'two' } }));
      await expect(loadBaseline(path)).rejects.toThrow(/Unsupported baseline format/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('does not misreport a directory read error as "not found"', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      await expect(loadBaseline(dir)).rejects.toThrow(/Failed to read baseline file/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('assertWritableBaselinePath', () => {
  it('allows a nonexistent path', async () => {
    await expect(assertWritableBaselinePath('/tmp/definitely-missing-cg-baseline.json')).resolves.toBeUndefined();
  });

  it('allows overwriting an existing valid baseline', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'baseline.json');
      await writeBaseline([finding()], path);
      await expect(assertWritableBaselinePath(path)).resolves.toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses a directory target (greedy [file] argument trap)', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      await expect(assertWritableBaselinePath(dir)).rejects.toThrow(/is a directory/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('refuses to overwrite an existing non-baseline file (source-file protection)', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-baseline-'));
    try {
      const path = resolve(dir, 'app.ts');
      await writeFile(path, 'export const x = 1;\n');
      await expect(assertWritableBaselinePath(path)).rejects.toThrow(/Refusing to overwrite/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
