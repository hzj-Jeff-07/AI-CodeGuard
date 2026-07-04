import { Command } from 'commander';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const DEFAULT_CONFIG = `# AI-CodeGuard Configuration
# See: https://github.com/user/ai-codeguard

scan:
  include:
    - "src/**/*.{ts,js,py,go,java}"
    - "lib/**/*.{ts,js,py,go,java}"
  exclude:
    - "node_modules"
    - "dist"
    - "build"
    - "**/*.test.*"
    - "**/*.spec.*"

rules:
  preset: owasp-top-10
  # custom: ./my-rules/
  # disable:
  #   - CG-050

llm:
  provider: claude
  model: claude-sonnet-5
  maxConcurrency: 5
  # maxCostUSD: 1.00

cache:
  enabled: true
  directory: .codeguard-cache
  ttl: 86400

output:
  format: text
  # file: codeguard-report.sarif
`;

export function createInitCommand(): Command {
  return new Command('init')
    .description('Initialize a .codeguard.yml configuration file')
    .option('--force', 'Overwrite existing config', false)
    .action(async (opts) => {
      const configPath = resolve(process.cwd(), '.codeguard.yml');

      try {
        const { existsSync } = await import('node:fs');
        if (existsSync(configPath) && !opts.force) {
          console.log('.codeguard.yml already exists. Use --force to overwrite.');
          return;
        }

        await writeFile(configPath, DEFAULT_CONFIG, 'utf-8');
        console.log('Created .codeguard.yml');
        console.log('');
        console.log('Next steps:');
        console.log('  1. Edit .codeguard.yml to match your project');
        console.log('  2. Set ANTHROPIC_API_KEY or OPENAI_API_KEY env var');
        console.log('  3. Run: ai-codeguard scan ./src');
      } catch (error) {
        console.error('Init failed:', error instanceof Error ? error.message : error);
        process.exitCode = 1;
      }
    });
}
