import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { parse, detectLanguage } from '../../src/parser/index.js';
import { getRules, runRules } from '../../src/rules/index.js';

// ── Precision harness ─────────────────────────────────────────────
//
// Scans the labeled corpus in tests/corpus/ and compares Stage 1 findings
// against ground-truth annotations (`codeguard-expect CG-XXX` trailing
// comments). Unlike the unit tests (single-line detect/ignore pairs), the
// corpus is realistic mixed code, so it measures what the tool actually
// gets right and wrong:
//
//   TP — an annotated vulnerability the scanner reported (same rule, same line)
//   FN — an annotated vulnerability the scanner missed
//   FP — a report on a line with no annotation for that rule
//
// The thresholds at the bottom are a RATCHET, set from the current measured
// values: they may be raised as precision/recall improve, but a change that
// lowers either below the ratchet fails this test. Known-miss cases (the
// corpus documents each) are still annotated as ground truth, so recall
// honestly reflects the flat-node model's limits instead of hiding them.

const CORPUS_DIR = resolve(__dirname, '../corpus');
const EXPECT_DIRECTIVE = /codeguard-expect\s+((?:CG-\d+[\s,]*)+)/;

interface Expectation {
  file: string;
  line: number;
  ruleId: string;
}

interface Reported {
  file: string;
  line: number;
  ruleId: string;
}

function parseExpectations(file: string, source: string): Expectation[] {
  const expectations: Expectation[] = [];
  source.split('\n').forEach((text, index) => {
    const match = EXPECT_DIRECTIVE.exec(text);
    if (!match) return;
    for (const ruleId of match[1].split(/[\s,]+/).filter(Boolean)) {
      expectations.push({ file, line: index + 1, ruleId: ruleId.toUpperCase() });
    }
  });
  return expectations;
}

async function scanCorpus(): Promise<{ expectations: Expectation[]; reported: Reported[] }> {
  const rules = getRules();
  const expectations: Expectation[] = [];
  const reported: Reported[] = [];

  for (const name of (await readdir(CORPUS_DIR)).sort()) {
    if (!extname(name)) continue;
    const file = name;
    const source = await readFile(resolve(CORPUS_DIR, name), 'utf-8');
    const language = detectLanguage(name);
    if (!language) throw new Error(`corpus file with undetectable language: ${name}`);

    expectations.push(...parseExpectations(file, source));

    const tree = await parse(source, language);
    for (const node of runRules(tree, rules, file)) {
      reported.push({ file, line: node.location.start.line, ruleId: node.ruleId });
    }
  }

  return { expectations, reported };
}

function keyOf(entry: { file: string; line: number; ruleId: string }): string {
  return `${entry.file}:${entry.line}:${entry.ruleId}`;
}

describe('precision corpus', () => {
  it('meets the precision/recall ratchet', async () => {
    const { expectations, reported } = await scanCorpus();
    expect(expectations.length).toBeGreaterThan(0);

    const expectedKeys = new Set(expectations.map(keyOf));
    const reportedKeys = new Set(reported.map(keyOf));

    const truePositives = [...expectedKeys].filter(k => reportedKeys.has(k));
    const falseNegatives = [...expectedKeys].filter(k => !reportedKeys.has(k));
    const falsePositives = [...reportedKeys].filter(k => !expectedKeys.has(k));

    const precision = truePositives.length / (truePositives.length + falsePositives.length);
    const recall = truePositives.length / (truePositives.length + falseNegatives.length);

    // Human-readable report (visible with `npm run precision`).
    const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
    console.log('\n── precision corpus report ──');
    console.log(`expected: ${expectedKeys.size}  reported: ${reportedKeys.size}`);
    console.log(`TP: ${truePositives.length}  FN: ${falseNegatives.length}  FP: ${falsePositives.length}`);
    console.log(`precision: ${pct(precision)}  recall: ${pct(recall)}`);
    if (falseNegatives.length > 0) console.log(`missed (FN): ${falseNegatives.join(', ')}`);
    if (falsePositives.length > 0) console.log(`spurious (FP): ${falsePositives.join(', ')}`);

    // ── RATCHET ── raise when the tool improves; never lower silently.
    // Current measured baseline: precision 95.8% (23 TP / 1 FP — the planted
    // str.find-as-Mongo trap), recall 92.0% (2 FN — the two documented
    // dataflow-blind two-step cases). The realworld.* corpus files pin the
    // false-positive classes found by scanning fastify/flask/juice-shop
    // (docs/dev/REALWORLD.md).
    expect(precision).toBeGreaterThanOrEqual(0.958);
    expect(recall).toBeGreaterThanOrEqual(0.92);
  });
});
