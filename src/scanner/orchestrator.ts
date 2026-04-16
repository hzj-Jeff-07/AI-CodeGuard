import fg from 'fast-glob';
import { readFile, stat } from 'node:fs/promises';
import { relative } from 'node:path';
import type { CodeGuardConfig, ScanResult, Finding, SuspiciousNode, SkippedFile, OutputFormat, Severity } from '../types/index.js';
import { parse, detectLanguage, getSupportedExtensions } from '../parser/index.js';
import { loadRules, runRules } from '../rules/index.js';
import { generateReport } from '../reporter/index.js';
import { analyzeFindings, type AnalyzeFindingsDependencies } from '../analyzer/index.js';

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export interface ScanOptions {
  paths: string[];
  config: CodeGuardConfig;
  fix: boolean;
  dryRun: boolean;
  output: OutputFormat;
  outputFile?: string;
  verbose: boolean;
  minSeverity?: Severity;
}

export async function scan(
  options: ScanOptions,
  dependencies: AnalyzeFindingsDependencies = {},
): Promise<ScanResult> {
  const startTime = Date.now();

  const files = await discoverFiles(options.paths, options.config);

  const rules = await loadRules({
    preset: options.config.rules.preset,
    custom: options.config.rules.custom,
    disable: options.config.rules.disable,
  });

  const allSuspicious: SuspiciousNode[] = [];
  const skipped: SkippedFile[] = [];

  for (const file of files) {
    const language = detectLanguage(file);
    if (!language) {
      skipped.push({ file, reason: 'Unsupported language' });
      continue;
    }

    try {
      const source = await readFile(file, 'utf-8');
      const tree = await parse(source, language);
      const suspicious = runRules(tree, rules, file);
      allSuspicious.push(...suspicious);
    } catch (error) {
      skipped.push({
        file,
        reason: error instanceof Error ? error.message : 'Parse error',
      });
    }
  }

  const stage1Findings = createStage1Findings(allSuspicious, rules);

  let findings = stage1Findings;
  let llmCalls = 0;
  let estimatedCost = 0;

  if (!options.dryRun && allSuspicious.length > 0) {
    const analyzed = await analyzeFindings({
      findings: stage1Findings,
      suspiciousNodes: allSuspicious,
      llm: options.config.llm,
      fix: options.fix,
    }, dependencies);

    findings = analyzed.findings;
    llmCalls = analyzed.llmCalls;
    estimatedCost = analyzed.estimatedCost;
  }

  if (options.minSeverity) {
    const minRank = SEVERITY_RANK[options.minSeverity];
    findings = findings.filter(f => SEVERITY_RANK[f.severity] >= minRank);
  }

  const result: ScanResult = {
    files: files.length,
    suspicious: allSuspicious.length,
    findings,
    skipped,
    duration: Date.now() - startTime,
    llmCalls,
    estimatedCost,
  };

  const report = await generateReport(result, options.output, options.outputFile);

  if (!options.outputFile) {
    process.stdout.write(report);
    if (options.output !== 'text') {
      process.stdout.write('\n');
    }
  }

  return result;
}

function createStage1Findings(
  suspiciousNodes: SuspiciousNode[],
  rules: Awaited<ReturnType<typeof loadRules>>,
): Finding[] {
  return suspiciousNodes.map((s, i) => ({
    id: `finding-${i + 1}`,
    ruleId: s.ruleId,
    severity: rules.find(r => r.id === s.ruleId)?.severity ?? 'medium',
    title: s.ruleName,
    description: `Potential ${s.ruleName} detected. ${
      s.confidence >= 0.8 ? 'High confidence pre-filter match.' : 'Moderate confidence — LLM analysis recommended.'
    }`,
    file: relative(process.cwd(), s.file).replace(/\\/g, '/'),
    location: s.location,
    snippet: s.snippet,
  }));
}

async function discoverFiles(
  paths: string[],
  config: CodeGuardConfig,
): Promise<string[]> {
  let patterns: string[];
  if (paths.length > 0) {
    const expanded: string[][] = await Promise.all(
      paths.map(async p => {
        const normalizedPath = p.replace(/\\/g, '/');
        try {
          const info = await stat(p);
          if (info.isFile()) return [normalizedPath];
        } catch {
          // Path doesn't exist yet — treat as glob pattern
          return [normalizedPath];
        }
        return config.scan.include.map(inc => `${normalizedPath}/${inc}`);
      }),
    );
    patterns = expanded.flat();
  } else {
    patterns = config.scan.include;
  }

  const supportedExts = getSupportedExtensions();

  const files = await fg(patterns, {
    ignore: config.scan.exclude,
    absolute: true,
    onlyFiles: true,
    dot: false,
  });

  return files.filter(f => supportedExts.some(ext => f.endsWith(ext)));
}
