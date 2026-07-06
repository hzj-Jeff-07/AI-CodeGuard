import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import { createRulesCommand } from '../../src/cli/commands/rules.js';

const FIXTURES_DIR = resolve(__dirname, '../fixtures');
const originalCwd = process.cwd();

async function withTempDir<T>(fn: (tempDir: string) => Promise<T>): Promise<T> {
  const tempDir = await mkdtemp(resolve(FIXTURES_DIR, 'tmp-rules-command-'));

  try {
    return await fn(tempDir);
  } finally {
    process.chdir(originalCwd);
    await rm(tempDir, { recursive: true, force: true });
  }
}

function makeRuleYaml(id: string, functionName: string): string {
  return `id: ${id}
name: ${id} rule
severity: high
category: injection
languages:
  - typescript
description: Detects ${functionName} calls
patterns:
  - type: function_call
    function:
      match:
        - ${functionName}
`;
}

function captureOutput() {
  const log = vi.spyOn(console, 'log').mockImplementation(() => {});
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  return { log, error };
}

async function runCommand(command: Command, args: string[]): Promise<void> {
  command.exitOverride();
  await command.parseAsync(['node', 'rules', ...args], { from: 'node' });
}

describe('rules command', () => {
  beforeEach(() => {
    process.exitCode = undefined;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.chdir(originalCwd);
    process.exitCode = undefined;
  });

  it('lists built-in rules by default', async () => {
    const output = captureOutput();

    await runCommand(createRulesCommand(), []);

    expect(output.log).toHaveBeenCalledWith('  AI-CodeGuard Rules');
    expect(output.log).toHaveBeenCalledWith(expect.stringContaining('CG-001'));
    expect(output.log).toHaveBeenCalledWith(expect.stringContaining('Total: 16 rules'));
  });

  it('validates a custom rule file', async () => {
    await withTempDir(async tempDir => {
      const output = captureOutput();
      const ruleFile = resolve(tempDir, 'custom.yml');
      await writeFile(ruleFile, makeRuleYaml('CR-301', 'customExec'));

      await runCommand(createRulesCommand(), ['validate', ruleFile]);

      expect(output.log).toHaveBeenCalledWith('Custom rules validated successfully.');
      expect(output.log).toHaveBeenCalledWith('Files: 1');
      expect(output.log).toHaveBeenCalledWith('Rules: 1');
      expect(output.log).toHaveBeenCalledWith('Rule IDs: CR-301');
      expect(process.exitCode).toBeUndefined();
    });
  });

  it('reports validation errors for invalid rules', async () => {
    await withTempDir(async tempDir => {
      const output = captureOutput();
      const ruleFile = resolve(tempDir, 'invalid.yml');
      await writeFile(ruleFile, 'rules: [');

      await runCommand(createRulesCommand(), ['validate', ruleFile]);

      expect(output.error).toHaveBeenCalledWith(
        expect.stringContaining('Rules validate failed:'),
        expect.stringContaining('Failed to parse custom rules file'),
      );
      expect(process.exitCode).toBe(2);
    });
  });

  it('creates a custom rule scaffold', async () => {
    await withTempDir(async tempDir => {
      const output = captureOutput();
      process.chdir(tempDir);

      await runCommand(createRulesCommand(), ['create', 'sample-rule.yml']);

      const createdFile = resolve(tempDir, 'sample-rule.yml');
      const content = await readFile(createdFile, 'utf-8');
      expect(existsSync(createdFile)).toBe(true);
      expect(content).toContain('id: CR-100');
      expect(content).toContain('match:');
      expect(output.log).toHaveBeenCalledWith('Created sample-rule.yml');
    });
  });

  it('does not overwrite an existing custom rule scaffold without force', async () => {
    await withTempDir(async tempDir => {
      const output = captureOutput();
      const targetFile = resolve(tempDir, 'sample-rule.yml');
      process.chdir(tempDir);
      await writeFile(targetFile, 'existing-content\n');

      await runCommand(createRulesCommand(), ['create', 'sample-rule.yml']);

      const content = await readFile(targetFile, 'utf-8');
      expect(content).toBe('existing-content\n');
      expect(output.log).toHaveBeenCalledWith('sample-rule.yml already exists. Use --force to overwrite.');
    });
  });

  it('overwrites an existing custom rule scaffold with force', async () => {
    await withTempDir(async tempDir => {
      const output = captureOutput();
      const targetFile = resolve(tempDir, 'sample-rule.yml');
      process.chdir(tempDir);
      await writeFile(targetFile, 'existing-content\n');

      await runCommand(createRulesCommand(), ['create', 'sample-rule.yml', '--force']);

      const content = await readFile(targetFile, 'utf-8');
      expect(content).toContain('id: CR-100');
      expect(output.log).toHaveBeenCalledWith('Created sample-rule.yml');
    });
  });
});
