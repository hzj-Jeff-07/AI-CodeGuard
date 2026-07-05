import { describe, it, expect } from 'vitest';
import { analyzeFindings } from '../../src/analyzer/index.js';
import type { ASTNode, Finding, SuspiciousNode } from '../../src/types/index.js';

/**
 * Opt-in acceptance test against the REAL Claude provider.
 *
 * Skipped by default so `npm run test:run` stays offline and free. To run it:
 *
 *   CODEGUARD_E2E=1 ANTHROPIC_API_KEY=sk-... npx vitest run tests/integration/llm-provider.test.ts
 *
 * Model defaults to Haiku to keep the cost of one acceptance run negligible;
 * override with CODEGUARD_E2E_MODEL.
 */
const apiKey = process.env.ANTHROPIC_API_KEY ?? '';
const enabled = process.env.CODEGUARD_E2E === '1' && apiKey.length > 0;
const model = process.env.CODEGUARD_E2E_MODEL ?? 'claude-haiku-4-5-20251001';

const SNIPPET = 'db.query("SELECT * FROM users WHERE id = " + req.params.id)';

function makeNode(): ASTNode {
  return {
    type: 'function_call',
    rawType: 'call_expression',
    text: SNIPPET,
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    children: [],
    parent: null,
    fields: {},
  };
}

function makeFinding(): Finding {
  return {
    id: 'finding-1',
    ruleId: 'CG-001',
    severity: 'critical',
    title: 'SQL Injection',
    description: 'Potential SQL Injection detected.',
    file: 'src/routes/users.ts',
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    snippet: SNIPPET,
  };
}

function makeSuspiciousNode(): SuspiciousNode {
  return {
    file: 'src/routes/users.ts',
    language: 'typescript',
    ruleId: 'CG-001',
    ruleName: 'SQL Injection',
    node: makeNode(),
    location: { start: { line: 3, column: 2 }, end: { line: 3, column: 2 + SNIPPET.length } },
    snippet: SNIPPET,
    context: `app.get('/users/:id', (req, res) => {\n  ${SNIPPET}.then(rows => res.json(rows));\n});`,
    confidence: 0.8,
    metadata: { method: 'query', object: 'db' },
  };
}

describe.skipIf(!enabled)('Stage 2 real Claude provider (opt-in E2E)', () => {
  it('confirms an obvious SQL injection end-to-end', { timeout: 60_000 }, async () => {
    const result = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: {
        provider: 'claude',
        model,
        apiKey,
        maxConcurrency: 1,
        maxCostUSD: 0.5,
      },
      fix: false,
    });

    expect(result.llmCalls).toBe(1);
    expect(result.estimatedCost).toBeGreaterThan(0);
    expect(result.dismissed).toHaveLength(0);

    const [finding] = result.findings;
    expect(finding.llmAnalysis?.confirmed).toBe(true);
    expect(finding.llmAnalysis?.reasoning).toBeTruthy();
    expect(finding.llmAnalysis?.confidence).toBeGreaterThan(0.5);
  });
});
