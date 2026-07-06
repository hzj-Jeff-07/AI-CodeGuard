import { Command, Option } from 'commander';
import { loadConfig } from '../../config/index.js';
import { scan } from '../../scanner/index.js';
import type { Finding, OutputFormat, Severity } from '../../types/index.js';
import { meetsSeverity } from '../../types/index.js';

// The build-failing threshold: any severity, or `none` to never fail the
// build on findings (report-only). Exported for testing.
export type FailOn = Severity | 'none';

export function shouldFailBuild(findings: Pick<Finding, 'severity'>[], failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  return findings.some(f => meetsSeverity(f.severity, failOn));
}

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
    .addOption(
      new Option('--fail-on <level>', 'Exit non-zero when a finding at or above this severity is reported (use "none" to never fail on findings)')
        .choices(['low', 'medium', 'high', 'critical', 'none'])
        .default('high'),
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

        // Exit non-zero when a reported finding meets the fail-on threshold
        // (default: high — preserving the prior "fail on high/critical" gate).
        if (shouldFailBuild(result.findings, opts.failOn as FailOn)) {
          process.exitCode = 1;
        }
      } catch (error) {
        console.error('Scan failed:', error instanceof Error ? error.message : error);
        process.exitCode = 2;
      }
    });
}
