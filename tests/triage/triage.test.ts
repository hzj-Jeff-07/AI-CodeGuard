import { describe, it, expect } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { resolve, basename } from 'node:path';
import { scan } from '../../src/scanner/orchestrator.js';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';
import type { AnalyzeFindingsDependencies, AnalyzeWithLLM } from '../../src/analyzer/index.js';
import type { Finding } from '../../src/types/index.js';

// ── Stage 2 triage harness ────────────────────────────────────────
//
// The product's core claim is that Stage 2 (LLM) triages Stage 1 findings —
// confirming real vulnerabilities and dismissing false positives. This
// harness measures that claim on a labeled corpus (tests/corpus-triage/):
// every line Stage 1 flags carries a ground-truth verdict annotation,
// `codeguard-real CG-XXX` (should be CONFIRMED) or `codeguard-fp CG-XXX`
// (should be DISMISSED).
//
// Metrics:
//   confirm-recall — labeled-real findings the LLM confirmed / all real
//   fp-dismiss-rate — labeled-fp findings the LLM dismissed / all fp
//   triage accuracy — correct verdicts / all labeled findings
//
// The always-on tests validate the harness arithmetic with scripted
// providers (they say nothing about LLM quality). The real measurement is
// opt-in, mirroring tests/integration/llm-provider.test.ts:
//
//   CODEGUARD_E2E=1 ANTHROPIC_API_KEY=sk-... npm run triage

const CORPUS_DIR = resolve(__dirname, '../corpus-triage');
const LABEL_DIRECTIVE = /codeguard-(real|fp)\s+(CG-\d+)/;

const apiKey = process.env.ANTHROPIC_API_KEY ?? '';
const e2eEnabled = process.env.CODEGUARD_E2E === '1' && apiKey.length > 0;
const e2eModel = process.env.CODEGUARD_E2E_MODEL ?? 'claude-haiku-4-5-20251001';

interface Label {
  file: string; // basename
  line: number;
  ruleId: string;
  verdict: 'real' | 'fp';
}

async function loadLabels(): Promise<Label[]> {
  const labels: Label[] = [];
  for (const name of (await readdir(CORPUS_DIR)).sort()) {
    const source = await readFile(resolve(CORPUS_DIR, name), 'utf-8');
    source.split('\n').forEach((text, index) => {
      const match = LABEL_DIRECTIVE.exec(text);
      if (match) {
        labels.push({ file: name, line: index + 1, ruleId: match[2], verdict: match[1] as 'real' | 'fp' });
      }
    });
  }
  return labels;
}

function keyOf(entry: { file: string; line: number; ruleId: string }): string {
  return `${entry.file}:${entry.line}:${entry.ruleId}`;
}

function findingKey(f: Finding): string {
  return keyOf({ file: basename(f.file), line: f.location.start.line, ruleId: f.ruleId });
}

interface TriageReport {
  total: number;
  confirmRecall: number;
  fpDismissRate: number;
  accuracy: number;
  wrong: string[];
  unlabeled: string[];
}

async function runTriage(dependencies: AnalyzeFindingsDependencies): Promise<TriageReport> {
  const labels = await loadLabels();
  expect(labels.length).toBeGreaterThan(0);

  const originalWrite = process.stdout.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  let result;
  try {
    result = await scan({
      paths: [CORPUS_DIR],
      config: {
        ...DEFAULT_CONFIG,
        llm: { ...DEFAULT_CONFIG.llm, apiKey: apiKey || 'test-key', model: e2eModel },
        // Disable the disk cache so repeated runs measure the model, not a replay.
        cache: { ...DEFAULT_CONFIG.cache, enabled: false },
      },
      fix: false,
      dryRun: false,
      output: 'json',
      verbose: false,
    }, dependencies);
  } finally {
    process.stdout.write = originalWrite;
  }

  const confirmed = new Set(result.findings.map(findingKey));
  const dismissed = new Set((result.dismissedFindings ?? []).map(findingKey));

  const realLabels = labels.filter(l => l.verdict === 'real');
  const fpLabels = labels.filter(l => l.verdict === 'fp');

  const confirmedReal = realLabels.filter(l => confirmed.has(keyOf(l)));
  const dismissedFp = fpLabels.filter(l => dismissed.has(keyOf(l)));
  const wrong = [
    ...realLabels.filter(l => dismissed.has(keyOf(l))).map(l => `${keyOf(l)} real→dismissed`),
    ...fpLabels.filter(l => confirmed.has(keyOf(l))).map(l => `${keyOf(l)} fp→confirmed`),
  ];

  // Integrity: every Stage 1 finding must be covered by a label, and every
  // label must have fired — otherwise the corpus and the rules drifted apart.
  const labeledKeys = new Set(labels.map(keyOf));
  const unlabeled = [...confirmed, ...dismissed].filter(k => !labeledKeys.has(k));
  const silent = labels.filter(l => !confirmed.has(keyOf(l)) && !dismissed.has(keyOf(l)));
  expect(unlabeled, `Stage 1 findings without a triage label: ${unlabeled.join(', ')}`).toHaveLength(0);
  expect(silent.map(keyOf), 'labeled lines Stage 1 no longer fires on').toHaveLength(0);

  return {
    total: labels.length,
    confirmRecall: confirmedReal.length / realLabels.length,
    fpDismissRate: dismissedFp.length / fpLabels.length,
    accuracy: (confirmedReal.length + dismissedFp.length) / labels.length,
    wrong,
    unlabeled,
  };
}

function scriptedProvider(confirmed: boolean): AnalyzeWithLLM {
  return async () => ({
    text: JSON.stringify({ confirmed, confidence: 0.9, reasoning: 'scripted verdict for harness validation' }),
    inputTokens: 100,
    outputTokens: 20,
  });
}

function deps(provider: AnalyzeWithLLM): AnalyzeFindingsDependencies {
  return { providers: { claude: provider, openai: provider } };
}

describe('triage harness arithmetic (scripted providers)', () => {
  it('confirm-everything provider → confirm-recall 1, fp-dismiss-rate 0', async () => {
    const report = await runTriage(deps(scriptedProvider(true)));
    expect(report.confirmRecall).toBe(1);
    expect(report.fpDismissRate).toBe(0);
  });

  it('dismiss-everything provider → confirm-recall 0, fp-dismiss-rate 1', async () => {
    const report = await runTriage(deps(scriptedProvider(false)));
    expect(report.confirmRecall).toBe(0);
    expect(report.fpDismissRate).toBe(1);
  });
});

describe.skipIf(!e2eEnabled)('Stage 2 triage accuracy (real provider, opt-in)', () => {
  it('measures confirm-recall and fp-dismiss-rate against ground truth', async () => {
    const report = await runTriage({});

    const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
    console.log(`\n── Stage 2 triage report (${e2eModel}) ──`);
    console.log(`labeled findings: ${report.total}`);
    console.log(`confirm-recall (real vulns confirmed): ${pct(report.confirmRecall)}`);
    console.log(`fp-dismiss-rate (false positives dismissed): ${pct(report.fpDismissRate)}`);
    console.log(`triage accuracy: ${pct(report.accuracy)}`);
    if (report.wrong.length > 0) console.log(`wrong verdicts: ${report.wrong.join('; ')}`);

    // Deliberately loose: this is a measurement, and model behavior varies.
    // The floor only catches catastrophic breakage (e.g. a prompt regression
    // that confirms or dismisses everything).
    expect(report.accuracy).toBeGreaterThanOrEqual(0.6);
  }, 120_000);
});
