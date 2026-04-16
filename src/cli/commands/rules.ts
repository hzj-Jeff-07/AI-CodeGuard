import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Command } from 'commander';
import { loadConfig } from '../../config/index.js';
import { validateCustomRules } from '../../rules/custom.js';
import { getAllRuleIds, getRules } from '../../rules/index.js';
import { scan } from '../../scanner/index.js';
import type { CodeGuardConfig, OutputFormat } from '../../types/index.js';

const DEFAULT_CUSTOM_RULE = `id: CR-100
name: Example custom rule
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

export function createRulesCommand(): Command {
  const command = new Command('rules')
    .description('List and manage detection rules')
    .option('--list', 'List all available rules', true)
    .action(() => {
      printBuiltInRules();
    });

  command
    .command('validate')
    .description('Validate custom rule file or directory')
    .argument('<path>', 'Path to custom rule YAML file or directory')
    .action(async (customPath: string) => {
      try {
        const validated = await validateCustomRules(customPath, getAllRuleIds());
        const ruleIds = validated.definitions.map(definition => definition.id);

        console.log('Custom rules validated successfully.');
        console.log(`Files: ${validated.files.length}`);
        console.log(`Rules: ${validated.definitions.length}`);
        console.log(`Rule IDs: ${ruleIds.join(', ')}`);
      } catch (error) {
        console.error('Rules validate failed:', error instanceof Error ? error.message : error);
        process.exitCode = 2;
      }
    });

  command
    .command('create')
    .description('Create a custom rule YAML scaffold')
    .argument('<file>', 'File to create')
    .option('--force', 'Overwrite existing file', false)
    .action(async (filePath: string, opts: { force: boolean }) => {
      const resolvedPath = resolve(process.cwd(), filePath);

      try {
        if (existsSync(resolvedPath) && !opts.force) {
          console.log(`${filePath} already exists. Use --force to overwrite.`);
          return;
        }

        await writeFile(resolvedPath, DEFAULT_CUSTOM_RULE, 'utf-8');
        console.log(`Created ${filePath}`);
      } catch (error) {
        console.error('Rules create failed:', error instanceof Error ? error.message : error);
        process.exitCode = 1;
      }
    });

  command
    .command('test')
    .description('Run Stage 1 scan using only custom rules')
    .argument('<rulesPath>', 'Path to custom rule YAML file or directory')
    .argument('[paths...]', 'Files or directories to scan', ['.'])
    .option('-o, --output <format>', 'Output format: text, json, sarif', 'text')
    .option('-f, --output-file <file>', 'Write report to file')
    .option('--config <path>', 'Path to config file')
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (rulesPath: string, paths: string[], opts) => {
      try {
        const config = await loadConfig(opts.config);
        const outputFormat = (opts.output as OutputFormat) ?? config.output.format;

        const result = await scan({
          paths,
          config: createRulesTestConfig(config, rulesPath),
          fix: false,
          dryRun: true,
          output: outputFormat,
          outputFile: opts.outputFile ?? config.output.file,
          verbose: opts.verbose,
        });

        const hasCritical = result.findings.some(
          finding => finding.severity === 'critical' || finding.severity === 'high',
        );
        if (hasCritical) {
          process.exitCode = 1;
        }
      } catch (error) {
        console.error('Rules test failed:', error instanceof Error ? error.message : error);
        process.exitCode = 2;
      }
    });

  return command;
}

function printBuiltInRules(): void {
  const rules = getRules();

  console.log('');
  console.log('  AI-CodeGuard Rules');
  console.log('  ' + '='.repeat(60));
  console.log('');

  const maxIdLen = Math.max(...rules.map(r => r.id.length));
  const maxNameLen = Math.max(...rules.map(r => r.name.length));

  console.log(
    `  ${'ID'.padEnd(maxIdLen)}  ${'Name'.padEnd(maxNameLen)}  ${'Severity'.padEnd(8)}  Languages`,
  );
  console.log('  ' + '-'.repeat(60));

  for (const rule of rules) {
    console.log(
      `  ${rule.id.padEnd(maxIdLen)}  ${rule.name.padEnd(maxNameLen)}  ${rule.severity.padEnd(8)}  ${rule.languages.join(', ')}`,
    );
  }

  console.log('');
  console.log(`  Total: ${rules.length} rules`);
  console.log('');
}

function createRulesTestConfig(config: CodeGuardConfig, rulesPath: string): CodeGuardConfig {
  return {
    ...config,
    rules: {
      ...config.rules,
      preset: 'none',
      custom: rulesPath,
      disable: [],
    },
  };
}
