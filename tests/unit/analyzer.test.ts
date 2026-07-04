import { describe, it, expect } from 'vitest';
import { analyzeFindings, type AnalyzeWithLLM } from '../../src/analyzer/index.js';
import { MemoryCacheStore } from '../../src/cache/index.js';
import type { ASTNode, Finding, LLMConfig, SuspiciousNode } from '../../src/types/index.js';

function makeNode(): ASTNode {
  return {
    type: 'function_call',
    rawType: 'CallExpression',
    text: 'pool.query(userInput)',
    location: {
      start: { line: 10, column: 0 },
      end: { line: 10, column: 22 },
    },
    children: [],
    parent: null,
    fields: {},
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
      end: { line: 10, column: 22 },
    },
    snippet: 'pool.query(userInput)',
    ...overrides,
  };
}

function makeSuspiciousNode(overrides: Partial<SuspiciousNode> = {}): SuspiciousNode {
  return {
    file: 'src/db.ts',
    language: 'typescript',
    ruleId: 'CG-001',
    ruleName: 'SQL Injection',
    node: makeNode(),
    location: {
      start: { line: 10, column: 0 },
      end: { line: 10, column: 22 },
    },
    snippet: 'pool.query(userInput)',
    context: 'const result = pool.query(userInput);',
    confidence: 0.9,
    metadata: {},
    ...overrides,
  };
}

function makeLLM(overrides: Partial<LLMConfig> = {}): LLMConfig {
  return {
    provider: 'claude',
    model: 'claude-sonnet-4-6',
    apiKey: 'test-key',
    maxConcurrency: 5,
    ...overrides,
  };
}

function makeConfirmedResponse(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    confirmed: true,
    confidence: 0.9,
    reasoning: 'User-controlled input reaches a dangerous sink.',
    ...overrides,
  });
}

describe('analyzeFindings', () => {
  it('uses the configured provider', async () => {
    let usedProvider = '';

    const result = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM({ provider: 'openai' }),
      fix: false,
    }, {
      providers: {
        claude: async () => {
          usedProvider = 'claude';
          return { text: makeConfirmedResponse(), inputTokens: 100, outputTokens: 50 };
        },
        openai: async () => {
          usedProvider = 'openai';
          return { text: makeConfirmedResponse(), inputTokens: 100, outputTokens: 50 };
        },
      },
    });

    expect(usedProvider).toBe('openai');
    expect(result.llmCalls).toBe(1);
    expect(result.findings[0].llmAnalysis?.confirmed).toBe(true);
  });

  it('throws when API key is missing', async () => {
    await expect(analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM({ apiKey: undefined }),
      fix: false,
    })).rejects.toThrow('LLM API key is required for Stage 2 analysis');
  });

  it('respects maxConcurrency while analyzing findings', async () => {
    let active = 0;
    let maxActive = 0;

    const provider: AnalyzeWithLLM = async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise(resolve => setTimeout(resolve, 10));
      active -= 1;
      return {
        text: makeConfirmedResponse(),
        inputTokens: 100,
        outputTokens: 50,
      };
    };

    const result = await analyzeFindings({
      findings: [
        makeFinding({ id: 'finding-1' }),
        makeFinding({ id: 'finding-2' }),
        makeFinding({ id: 'finding-3' }),
      ],
      suspiciousNodes: [
        makeSuspiciousNode(),
        makeSuspiciousNode(),
        makeSuspiciousNode(),
      ],
      llm: makeLLM({ maxConcurrency: 2 }),
      fix: false,
    }, {
      providers: {
        claude: provider,
      },
    });

    expect(maxActive).toBeLessThanOrEqual(2);
    expect(result.llmCalls).toBe(3);
  });

  it('stops new LLM calls after reaching maxCostUSD', async () => {
    const result = await analyzeFindings({
      findings: [
        makeFinding({ id: 'finding-1' }),
        makeFinding({ id: 'finding-2' }),
        makeFinding({ id: 'finding-3' }),
      ],
      suspiciousNodes: [
        makeSuspiciousNode(),
        makeSuspiciousNode(),
        makeSuspiciousNode(),
      ],
      llm: makeLLM({ maxConcurrency: 1, maxCostUSD: 1 }),
      fix: false,
    }, {
      providers: {
        claude: async () => ({
          text: makeConfirmedResponse(),
          inputTokens: 1_000_000,
          outputTokens: 0,
        }),
      },
    });

    expect(result.llmCalls).toBe(1);
    expect(result.estimatedCost).toBeGreaterThanOrEqual(1);
    expect(result.findings).toHaveLength(3);
    expect(result.findings.filter(finding => finding.llmAnalysis)).toHaveLength(1);
    expect(result.findings.filter(finding => !finding.llmAnalysis)).toHaveLength(2);
  });

  it('skips LLM calls when cache hits', async () => {
    let providerCalls = 0;
    const provider: AnalyzeWithLLM = async () => {
      providerCalls += 1;
      return { text: makeConfirmedResponse(), inputTokens: 100, outputTokens: 50 };
    };

    const cache = new MemoryCacheStore();

    const first = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM(),
      fix: false,
    }, { providers: { claude: provider }, cache });

    expect(first.llmCalls).toBe(1);
    expect(first.cacheHits).toBe(0);
    expect(providerCalls).toBe(1);

    const second = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM(),
      fix: false,
    }, { providers: { claude: provider }, cache });

    expect(second.llmCalls).toBe(0);
    expect(second.cacheHits).toBe(1);
    expect(providerCalls).toBe(1);
    expect(second.findings[0].llmAnalysis?.confirmed).toBe(true);
    expect(second.findings[0].description).toContain('cached');
  });

  it('does not double-count tokens via cached entries against budget', async () => {
    const cache = new MemoryCacheStore();
    const provider: AnalyzeWithLLM = async () => ({
      text: makeConfirmedResponse(),
      inputTokens: 1_000_000,
      outputTokens: 0,
    });

    await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM(),
      fix: false,
    }, { providers: { claude: provider }, cache });

    const replay = await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM({ maxCostUSD: 1 }),
      fix: false,
    }, { providers: { claude: provider }, cache });

    expect(replay.llmCalls).toBe(0);
    expect(replay.cacheHits).toBe(1);
    expect(replay.estimatedCost).toBe(0);
    expect(replay.findings).toHaveLength(1);
  });

  it('treats fix=true and fix=false as independent cache entries', async () => {
    const cache = new MemoryCacheStore();
    let providerCalls = 0;
    const provider: AnalyzeWithLLM = async () => {
      providerCalls += 1;
      return {
        text: JSON.stringify({
          confirmed: true,
          confidence: 0.9,
          reasoning: 'reason',
          fixDescription: 'use parameterized',
          fixCode: 'pool.query(?, [userInput])',
        }),
        inputTokens: 100,
        outputTokens: 50,
      };
    };

    await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM(),
      fix: false,
    }, { providers: { claude: provider }, cache });

    await analyzeFindings({
      findings: [makeFinding()],
      suspiciousNodes: [makeSuspiciousNode()],
      llm: makeLLM(),
      fix: true,
    }, { providers: { claude: provider }, cache });

    expect(providerCalls).toBe(2);
  });
});
