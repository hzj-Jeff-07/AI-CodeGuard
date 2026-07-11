import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { parseUnifiedDiff, loadChangedLines, overlapsChangedLines } from '../../src/scanner/diff.js';
import { scan } from '../../src/scanner/orchestrator.js';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';
import type { ScanOptions } from '../../src/scanner/orchestrator.js';

// ── parseUnifiedDiff ────────────────────────────────────────────

describe('parseUnifiedDiff', () => {
  it('collects added/modified new-side lines per file, stripping the b/ prefix', () => {
    const diff = [
      'diff --git a/src/app.ts b/src/app.ts',
      'index 111..222 100644',
      '--- a/src/app.ts',
      '+++ b/src/app.ts',
      '@@ -10,3 +10,4 @@ function handler() {',
      ' context',
      '-removed line',
      '+added line 11',
      '+added line 12',
      ' context',
      '@@ -40,2 +41,2 @@',
      ' context',
      '+added line 42',
      'diff --git a/lib/util.py b/lib/util.py',
      '--- a/lib/util.py',
      '+++ b/lib/util.py',
      '@@ -1,1 +1,2 @@',
      ' context',
      '+added line 2',
    ].join('\n');

    const changed = parseUnifiedDiff(diff);
    expect([...(changed.get('src/app.ts') ?? [])].sort((a, b) => a - b)).toEqual([11, 12, 42]);
    expect([...(changed.get('lib/util.py') ?? [])]).toEqual([2]);
  });

  it('ignores deleted files (+++ /dev/null)', () => {
    const diff = [
      '--- a/gone.ts',
      '+++ /dev/null',
      '@@ -1,3 +0,0 @@',
      '-first',
      '-second',
      '-third',
    ].join('\n');
    expect(parseUnifiedDiff(diff).size).toBe(0);
  });

  it('handles plain (non-git) headers and trailing timestamps', () => {
    const diff = [
      '--- app.ts\t2026-07-11 10:00:00',
      '+++ app.ts\t2026-07-11 10:05:00',
      '@@ -1,1 +1,1 @@',
      '-old',
      '+new',
    ].join('\n');
    expect([...(parseUnifiedDiff(diff).get('app.ts') ?? [])]).toEqual([1]);
  });

  it('does not advance the counter on the no-newline marker', () => {
    const diff = [
      '--- a/x.ts',
      '+++ b/x.ts',
      '@@ -1,2 +1,2 @@',
      ' context',
      '+last line',
      '\\ No newline at end of file',
    ].join('\n');
    expect([...(parseUnifiedDiff(diff).get('x.ts') ?? [])]).toEqual([2]);
  });

  it('does not misread hunk content that looks like diff structure', () => {
    // A deleted SQL comment renders as `--- x`; an added `++ i` renders as
    // `+++ i`. Hunk-length counting must keep both classified as body.
    const diff = [
      '--- a/q.sql',
      '+++ b/q.sql',
      '@@ -1,2 +1,2 @@',
      ' context',
      '--- legacy comment',
      '+++ count added',
      '@@ -10,1 +10,1 @@',
      '+real added line',
    ].join('\n');
    const changed = parseUnifiedDiff(diff);
    expect([...(changed.get('q.sql') ?? [])].sort((a, b) => a - b)).toEqual([2, 10]);
    expect(changed.size).toBe(1);
  });

  it('rejects text that is not a unified diff (silent-green footgun)', () => {
    expect(() => parseUnifiedDiff('{"findings": []}')).toThrow(/Not a unified diff/);
  });

  it('accepts an empty diff as "no changed lines"', () => {
    expect(parseUnifiedDiff('').size).toBe(0);
    expect(parseUnifiedDiff('\n').size).toBe(0);
  });
});

// ── overlapsChangedLines ────────────────────────────────────────

describe('overlapsChangedLines', () => {
  const changed = parseUnifiedDiff([
    '--- a/a.ts',
    '+++ b/a.ts',
    '@@ -4,1 +5,1 @@',
    '+line 5',
  ].join('\n'));

  it('matches when any line of the span is changed', () => {
    expect(overlapsChangedLines(changed, 'a.ts', 3, 6)).toBe(true);
    expect(overlapsChangedLines(changed, 'a.ts', 5, 5)).toBe(true);
  });

  it('does not match spans outside the changed lines or other files', () => {
    expect(overlapsChangedLines(changed, 'a.ts', 6, 9)).toBe(false);
    expect(overlapsChangedLines(changed, 'b.ts', 5, 5)).toBe(false);
  });

  it('treats an inverted span as its start line', () => {
    expect(overlapsChangedLines(changed, 'a.ts', 5, 1)).toBe(true);
  });
});

// ── loadChangedLines ────────────────────────────────────────────

describe('loadChangedLines', () => {
  it('reports a missing diff file clearly', async () => {
    await expect(loadChangedLines('/nonexistent/pr.diff')).rejects.toThrow(/Diff file not found/);
  });
});

// ── scan --diff end-to-end ──────────────────────────────────────

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

describe('scan with --diff filtering', () => {
  it('keeps findings on changed lines and drops the rest before Stage 2', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-diff-'));
    try {
      const file = resolve(dir, 'app.ts');
      // Two independent findings on known lines: line 1 and line 2.
      await writeFile(file, [
        'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);',
        'eval(userInput);',
        '',
      ].join('\n'));

      // The diff path must match Finding.file, which is cwd-relative.
      const relPath = relative(process.cwd(), file).replace(/\\/g, '/');
      const diffFile = resolve(dir, 'pr.diff');
      await writeFile(diffFile, [
        `--- a/${relPath}`,
        `+++ b/${relPath}`,
        '@@ -0,0 +1,1 @@',
        '+db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);',
        '',
      ].join('\n'));

      const report = resolve(dir, 'report.json');
      const result = await scan(makeOptions([file], { diffPath: diffFile, outputFile: report }));

      expect(result.findings.length).toBe(1);
      expect(result.findings[0].ruleId).toBe('CG-001');
      expect(result.findings[0].location.start.line).toBe(1);
      expect(result.diffFiltered).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('drops everything when the diff touches other files only', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-diff-'));
    try {
      const file = resolve(dir, 'app.ts');
      await writeFile(file, 'eval(userInput);\n');

      const diffFile = resolve(dir, 'pr.diff');
      await writeFile(diffFile, [
        '--- a/docs/README.md',
        '+++ b/docs/README.md',
        '@@ -1,0 +1,1 @@',
        '+docs only',
        '',
      ].join('\n'));

      const report = resolve(dir, 'report.json');
      const result = await scan(makeOptions([file], { diffPath: diffFile, outputFile: report }));

      expect(result.findings.length).toBe(0);
      expect(result.diffFiltered).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports diffFiltered as 0 when no diff is supplied', async () => {
    const dir = await mkdtemp(resolve(tmpdir(), 'cg-diff-'));
    try {
      const file = resolve(dir, 'app.ts');
      await writeFile(file, 'eval(userInput);\n');
      const report = resolve(dir, 'report.json');
      const result = await scan(makeOptions([file], { outputFile: report }));
      expect(result.diffFiltered).toBe(0);
      expect(result.findings.length).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
