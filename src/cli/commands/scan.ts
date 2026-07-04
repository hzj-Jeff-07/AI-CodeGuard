import { Command, Option } from 'commander';
import { loadConfig } from '../../config/index.js';
import { scan } from '../../scanner/index.js';
import type { OutputFormat, Severity } from '../../types/index.js';

export function createScanCommand(): Command {
  return new Command('scan')
    .description('Scan source code for security vulnerabilities')
    .argument('[paths...]', 'Files or directories to scan', ['.'])
    .addOption(
      new Option('-o, --output <format>', 'Output format')
        .choices(['text', 'json', 'sarif'])
        .default('text'),
    )
    .option('-f, --output-file <file>', 'Write report to file')
    .option('--fix', 'Generate fix suggestions (requires LLM)', false)
    .option('--dry-run', 'Run AST pre-filter only, no LLM calls', false)
    .option('--config <path>', 'Path to config file')
    .addOption(
      new Option('-s, --severity <level>', 'Minimum severity to report')
        .choices(['low', 'medium', 'high', 'critical']),
    )
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (paths: string[], opts) => {
      try {
        const config = await loadConfig(opts.config);

        // CLI options override config
        const outputFormat = (opts.output as OutputFormat) ?? config.output.format;

        const result = await scan({
          paths,
          config,
          fix: opts.fix,
          dryRun: opts.dryRun,
          output: outputFormat,
          outputFile: opts.outputFile ?? config.output.file,
          verbose: opts.verbose,
          minSeverity: opts.severity as Severity | undefined,
        });

        // Exit with non-zero if critical/high findings exist
        const hasCritical = result.findings.some(
          f => f.severity === 'critical' || f.severity === 'high'
        );
        if (hasCritical) {
          process.exitCode = 1;
        }
      } catch (error) {
        console.error('Scan failed:', error instanceof Error ? error.message : error);
        process.exitCode = 2;
      }
    });
}
