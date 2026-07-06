import { describe, it, expect } from 'vitest';
import { filterSuppressed } from '../../src/scanner/suppression.js';
import type { SuspiciousNode } from '../../src/types/index.js';

function node(line: number, ruleId = 'CG-001'): SuspiciousNode {
  return {
    file: 'test.js',
    language: 'javascript',
    ruleId,
    ruleName: ruleId,
    node: {
      type: 'function_call',
      rawType: 'call_expression',
      text: 'x',
      location: { start: { line, column: 0 }, end: { line, column: 1 } },
      children: [],
      parent: null,
      fields: {},
    },
    location: { start: { line, column: 0 }, end: { line, column: 1 } },
    snippet: 'x',
    context: '',
    confidence: 0.8,
    metadata: {},
  };
}

function keptLines(nodes: SuspiciousNode[], source: string): number[] {
  return filterSuppressed(nodes, source).kept.map(n => n.location.start.line);
}

describe('filterSuppressed', () => {
  it('keeps a finding on a line with no directive', () => {
    const r = filterSuppressed([node(1)], 'danger(x);');
    expect(r.kept).toHaveLength(1);
    expect(r.suppressed).toBe(0);
  });

  it('drops a finding on a line with a bare same-line directive', () => {
    const r = filterSuppressed([node(1)], 'danger(x); // codeguard-ignore');
    expect(r.kept).toHaveLength(0);
    expect(r.suppressed).toBe(1);
  });

  it('drops a finding when the directive names its rule', () => {
    const source = 'danger(x); // codeguard-ignore CG-001';
    expect(filterSuppressed([node(1, 'CG-001')], source).kept).toHaveLength(0);
  });

  it('keeps a finding when the directive names a different rule', () => {
    const source = 'danger(x); // codeguard-ignore CG-999';
    expect(filterSuppressed([node(1, 'CG-001')], source).kept).toHaveLength(1);
  });

  it('supports a comma/space-separated rule list', () => {
    const source = 'danger(x); // codeguard-ignore CG-001, CG-010';
    expect(filterSuppressed([node(1, 'CG-010')], source).kept).toHaveLength(0);
  });

  it('ignores trailing prose after the rule IDs', () => {
    const source = 'danger(x); // codeguard-ignore CG-001 reviewed: input is a constant';
    expect(filterSuppressed([node(1, 'CG-001')], source).kept).toHaveLength(0);
  });

  it('suppresses the following line with codeguard-ignore-next-line', () => {
    const source = '// codeguard-ignore-next-line\ndanger(x);';
    expect(filterSuppressed([node(2)], source).kept).toHaveLength(0);
  });

  it('does not let a same-line directive leak onto the next line', () => {
    // Line 1 has a trailing directive (for its own finding); line 2's finding
    // must survive — only codeguard-ignore-next-line targets the next line.
    const source = 'danger(a); // codeguard-ignore\ndanger(b);';
    expect(keptLines([node(1), node(2)], source)).toEqual([2]);
  });

  it('does not treat a same-line directive as a next-line one', () => {
    // A bare `codeguard-ignore` on the preceding line must NOT suppress the
    // finding below it (only `-next-line` does).
    const source = 'harmless(); // codeguard-ignore\ndanger(x);';
    expect(keptLines([node(2)], source)).toEqual([2]);
  });

  it('is case-insensitive on the rule ID', () => {
    const source = 'danger(x); // codeguard-ignore cg-001';
    expect(filterSuppressed([node(1, 'CG-001')], source).kept).toHaveLength(0);
  });

  it('counts every suppressed finding', () => {
    const source = [
      'danger(a); // codeguard-ignore',
      'danger(b); // codeguard-ignore CG-001',
      'danger(c);',
    ].join('\n');
    const r = filterSuppressed([node(1), node(2), node(3)], source);
    expect(r.suppressed).toBe(2);
    expect(keptLines([node(1), node(2), node(3)], source)).toEqual([3]);
  });
});
