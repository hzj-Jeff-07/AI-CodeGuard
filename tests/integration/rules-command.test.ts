import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Command } from 'commander';
import { createRulesCommand } from '../../src/cli/commands/rules.js';

const FIXTURES_DIR = resolve(__dirname, '../fixtures');
const originalCwd = process.cwd();

async function withTempDir<T>(fn: (tempDir: string) => Promise<T>): Promise<T> {
  const tempDir = await mkdtemp(resolve(FIXTURES_DIR, 'tmp-rules-test-command-'));

  try {
    return await fn(tempDir);
  } finally {
    process.chdir(originalCwd);
    await rm(tempDir, { recursive: true, force: true });
  }
}

function makeRuleYaml(): string {
  return `id: CR-401
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
`;
}

async function runCommand(command: Command, args: string[]): Promise<void> {
  command.exitOverride();
  await command.parseAsync(['node', 'rules', ...args], { from: 'node' });
}

describe('rules test command', () => {
  it('runs Stage 1-only custom rule scans without requiring API key', async () => {
    await withTempDir(async tempDir => {
      process.chdir(tempDir);

      const sourceFile = resolve(tempDir, 'custom-target.ts');
      const ruleFile = resolve(tempDir, 'custom-rule.yml');
      const configFile = resolve(tempDir, '.codeguard.yml');

      await writeFile(sourceFile, 'customExec(userInput);\n');
      await writeFile(ruleFile, makeRuleYaml());
      await writeFile(configFile, `llm:\n  provider: claude\n  model: claude-sonnet-4-6\n`);

      const writes: string[] = [];
      const originalWrite = process.stdout.write;
      process.stdout.write = ((chunk: string | Uint8Array) => {
        writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'));
        return true;
      }) as typeof process.stdout.write;

      try {
        await runCommand(createRulesCommand(), ['test', ruleFile, sourceFile, '--output', 'json']);
      } finally {
        process.stdout.write = originalWrite;
      }

      const output = writes.join('');
      const parsed = JSON.parse(output);

      expect(parsed.scan.llmCalls).toBe(0);
      expect(parsed.scan.estimatedCost).toBe(0);
      expect(parsed.findings).toHaveLength(1);
      expect(parsed.findings[0].ruleId).toBe('CR-401');
      expect(parsed.findings[0].file).toBe('custom-target.ts');
      expect(process.exitCode).toBe(1);
    });
  });
});
