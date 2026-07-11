import { Command, Option } from 'commander';
import { loadConfig } from '../../config/index.js';
import { scan } from '../../scanner/index.js';
import { assertWritableBaselinePath, writeBaseline } from '../../scanner/baseline.js';
import type { Finding, OutputFormat, Severity } from '../../types/index.js';
import { meetsSeverity } from '../../types/index.js';

const DEFAULT_BASELINE_FILE = '.codeguard-baseline.json';

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
        .choices(['text', 'json', 'sarif', 'github'])
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
    .option('--no-inline-suppression', 'Ignore inline codeguard-ignore comments (report everything, to audit what they hide)')
    .option('--baseline <file>', 'Only report findings not covered by this baseline file')
    .option('--diff <file>', 'Only report findings on lines added/modified by this unified diff (PR-bot mode; generate with `git diff base...head`)')
    .option('--write-baseline [file]', `Write current findings to a baseline file and exit 0 (default ${DEFAULT_BASELINE_FILE})`)
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (paths: string[], opts) => {
      try {
        if (opts.baseline && opts.writeBaseline) {
          // Writing while filtering would snapshot only the leftovers and
          // silently shrink the acknowledged set — force an explicit choice.
          console.error('Use either --baseline (compare) or --write-baseline (snapshot), not both.');
          process.exitCode = 2;
          return;
        }
        if (opts.severity && opts.writeBaseline) {
          // A severity-filtered snapshot acknowledges only part of the
          // findings; later unfiltered --baseline runs would resurface the
          // rest as "new". Baselines must come from unfiltered scans.
          console.error('Write baselines from an unfiltered scan: drop --severity when using --write-baseline.');
          process.exitCode = 2;
          return;
        }
        if (opts.diff && opts.writeBaseline) {
          // A diff-filtered snapshot acknowledges only the changed lines;
          // later unfiltered --baseline runs would resurface everything
          // else as "new". Baselines must come from unfiltered scans.
          console.error('Write baselines from an unfiltered scan: drop --diff when using --write-baseline.');
          process.exitCode = 2;
          return;
        }
        if (typeof opts.writeBaseline === 'string') {
          // Fail before any scanning cost if the target is a directory or an
          // existing non-baseline file (commander's optional [file] argument
          // greedily eats the next token, so `--write-baseline src` names the
          // OUTPUT, not a scan path).
          await assertWritableBaselinePath(opts.writeBaseline);
        }

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
          // commander maps --no-inline-suppression to inlineSuppression: false
          inlineSuppression: opts.inlineSuppression as boolean,
          baselinePath: opts.baseline as string | undefined,
          diffPath: opts.diff as string | undefined,
        });

        if (opts.writeBaseline) {
          // Snapshotting acknowledges the current findings; the run itself is
          // informational, so it never fails the build. Stage-2-dismissed
          // findings are acknowledged too — otherwise every later --baseline
          // run would re-pay LLM cost re-triaging them, and a flaky verdict
          // flip would fail CI on old, unchanged code.
          const baselineFile = typeof opts.writeBaseline === 'string' ? opts.writeBaseline : DEFAULT_BASELINE_FILE;
          const acknowledged = [...result.findings, ...(result.dismissedFindings ?? [])];
          await writeBaseline(acknowledged, baselineFile);
          console.error(`Baseline written: ${baselineFile} (${acknowledged.length} findings acknowledged, ${result.dismissedFindings?.length ?? 0} of them Stage 2 dismissals)`);
          return;
        }

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
