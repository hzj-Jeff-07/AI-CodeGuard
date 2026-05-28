import chalk from 'chalk';
import type { Finding, ScanResult } from '../types/index.js';

export function formatText(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.bold('  AI-CodeGuard Scan Results'));
  lines.push(chalk.dim('  ' + '='.repeat(50)));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(chalk.green('  ✓ No vulnerabilities found.'));
    lines.push('');
  } else {
    for (const finding of result.findings) {
      lines.push(formatFinding(finding));
      lines.push(chalk.dim('  ' + '-'.repeat(50)));
      lines.push('');
    }
  }

  lines.push(chalk.dim('  ' + '='.repeat(50)));
  lines.push(formatSummary(result));
  lines.push('');

  return lines.join('\n');
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const icon = finding.severity === 'critical' || finding.severity === 'high'
    ? chalk.red('✗')
    : chalk.yellow('⚠');

  const severityColor = {
    critical: chalk.bgRed.white.bold,
    high: chalk.red.bold,
    medium: chalk.yellow.bold,
    low: chalk.blue.bold,
  }[finding.severity];

  lines.push(`  ${icon} ${severityColor(finding.severity.toUpperCase())}  ${chalk.dim(finding.ruleId)}  ${chalk.bold(finding.title)}`);
  lines.push(`    ${chalk.cyan(finding.file)}:${finding.location.start.line}-${finding.location.end.line}`);
  lines.push('');

  // Code snippet
  const snippetLines = finding.snippet.split('\n');
  for (const sl of snippetLines.slice(0, 5)) {
    lines.push(`    ${chalk.dim('│')} ${sl}`);
  }
  if (snippetLines.length > 5) {
    lines.push(`    ${chalk.dim('│')} ${chalk.dim(`... ${snippetLines.length - 5} more lines`)}`);
  }

  // Fix suggestion
  if (finding.fix) {
    lines.push('');
    lines.push(`    ${chalk.green('Fix:')} ${finding.fix.description}`);
    const fixLines = finding.fix.code.split('\n');
    for (const fl of fixLines.slice(0, 3)) {
      lines.push(`    ${chalk.green('│')} ${fl}`);
    }
  }

  // LLM analysis (if available)
  if (finding.llmAnalysis) {
    lines.push('');
    const pct = (finding.llmAnalysis.confidence * 100).toFixed(0);
    lines.push(`    ${chalk.dim(`LLM Confidence: ${pct}% — ${finding.llmAnalysis.reasoning}`)}`);
  }

  return lines.join('\n');
}

function formatSummary(result: ScanResult): string {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  for (const f of result.findings) {
    counts[f.severity]++;
  }

  const parts: string[] = [];
  if (counts.critical > 0) parts.push(chalk.red(`${counts.critical} critical`));
  if (counts.high > 0) parts.push(chalk.red(`${counts.high} high`));
  if (counts.medium > 0) parts.push(chalk.yellow(`${counts.medium} medium`));
  if (counts.low > 0) parts.push(chalk.blue(`${counts.low} low`));

  const summaryStr = parts.length > 0
    ? `${result.findings.length} findings (${parts.join(', ')})`
    : 'No findings';

  const duration = (result.duration / 1000).toFixed(1);

  return [
    `  ${chalk.bold('Summary:')} ${summaryStr}`,
    `  Files scanned: ${result.files}  |  Suspicious: ${result.suspicious}  |  Duration: ${duration}s`,
    result.llmCalls > 0 ? `  LLM calls: ${result.llmCalls}  |  Estimated cost: $${result.estimatedCost.toFixed(2)}` : '',
    result.cacheHits > 0 ? `  Cache hits: ${result.cacheHits}` : '',
  ].filter(Boolean).join('\n');
}
