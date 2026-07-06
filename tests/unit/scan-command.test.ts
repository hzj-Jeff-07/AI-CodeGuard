import { describe, it, expect } from 'vitest';
import { shouldFailBuild } from '../../src/cli/commands/scan.js';
import { meetsSeverity } from '../../src/types/index.js';
import type { Severity } from '../../src/types/index.js';

function f(severity: Severity) {
  return { severity };
}

describe('meetsSeverity', () => {
  it('is true when severity equals the threshold', () => {
    expect(meetsSeverity('high', 'high')).toBe(true);
  });

  it('is true when severity exceeds the threshold', () => {
    expect(meetsSeverity('critical', 'high')).toBe(true);
  });

  it('is false when severity is below the threshold', () => {
    expect(meetsSeverity('medium', 'high')).toBe(false);
    expect(meetsSeverity('low', 'medium')).toBe(false);
  });
});

describe('shouldFailBuild', () => {
  it('defaults (high) fail the build on high or critical, not medium/low', () => {
    expect(shouldFailBuild([f('critical')], 'high')).toBe(true);
    expect(shouldFailBuild([f('high')], 'high')).toBe(true);
    expect(shouldFailBuild([f('medium'), f('low')], 'high')).toBe(false);
  });

  it('critical threshold only fails on a critical finding', () => {
    expect(shouldFailBuild([f('high'), f('medium')], 'critical')).toBe(false);
    expect(shouldFailBuild([f('critical')], 'critical')).toBe(true);
  });

  it('low threshold fails on any finding', () => {
    expect(shouldFailBuild([f('low')], 'low')).toBe(true);
    expect(shouldFailBuild([], 'low')).toBe(false);
  });

  it('none never fails the build, even with critical findings', () => {
    expect(shouldFailBuild([f('critical'), f('high')], 'none')).toBe(false);
  });

  it('empty findings never fail the build', () => {
    expect(shouldFailBuild([], 'high')).toBe(false);
  });
});
