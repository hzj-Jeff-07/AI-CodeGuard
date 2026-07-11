import fg from 'fast-glob';
import { readFile, stat } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import type { CodeGuardConfig, ScanResult, Finding, SuspiciousNode, SkippedFile, OutputFormat, Severity } from '../types/index.js';
import { SEVERITY_RANK } from '../types/index.js';
import { parse, detectLanguage, getSupportedExtensions } from '../parser/index.js';
import { loadRules, runRules } from '../rules/index.js';
import { generateReport } from '../reporter/index.js';
import { analyzeFindings, type AnalyzeFindingsDependencies } from '../analyzer/index.js';
import { FileCacheStore } from '../cache/index.js';
import { filterSuppressed } from './suppression.js';
import { filterAgainstBaseline, loadBaseline } from './baseline.js';
import { loadChangedLines, overlapsChangedLines } from './diff.js';

export interface ScanOptions {
  paths: string[];
  config: CodeGuardConfig;
  fix: boolean;
  dryRun: boolean;
  output: OutputFormat;
  outputFile?: string;
  verbose: boolean;
  minSeverity?: Severity;
  /** Apply inline `codeguard-ignore` directives. Default true; set false to audit what they hide. */
  inlineSuppression?: boolean;
  /** Path to a baseline file — findings covered by it are dropped (only new findings reported). */
  baselinePath?: string;
  /** Path to a unified diff — findings outside its added/modified lines are dropped (PR-bot mode). */
  diffPath?: string;
}

export async function scan(
  options: ScanOptions,
  dependencies: AnalyzeFindingsDependencies = {},
): Promise<ScanResult> {
  const startTime = Date.now();

  if (options.minSeverity && !(options.minSeverity in SEVERITY_RANK)) {
    throw new Error(
      `Invalid severity "${options.minSeverity}". Expected one of: low, medium, high, critical.`,
    );
  }

  const files = await discoverFiles(options.paths, options.config);

  const rules = await loadRules({
    preset: options.config.rules.preset,
    custom: options.config.rules.custom,
    disable: options.config.rules.disable,
  });

  const allSuspicious: SuspiciousNode[] = [];
  const skipped: SkippedFile[] = [];
  const suppressionEnabled = options.inlineSuppression !== false;
  let suppressed = 0;

  for (const file of files) {
    const language = detectLanguage(file);
    if (!language) {
      skipped.push({ file, reason: 'Unsupported language' });
      continue;
    }

    try {
      const source = await readFile(file, 'utf-8');
      const tree = await parse(source, language);
      const found = runRules(tree, rules, file);
      if (suppressionEnabled) {
        const result = filterSuppressed(found, source);
        suppressed += result.suppressed;
        allSuspicious.push(...result.kept);
      } else {
        allSuspicious.push(...found);
      }
    } catch (error) {
      skipped.push({
        file,
        reason: error instanceof Error ? error.message : 'Parse error',
      });
    }
  }

  let stage1Findings = createStage1Findings(allSuspicious, rules);
  let allSuspiciousKept = allSuspicious;
  let baselined = 0;

  if (options.baselinePath) {
    // Filter finding/suspicious pairs in tandem (they map 1:1 by index) so
    // baselined findings never reach Stage 2 — no wasted LLM calls.
    const baseline = await loadBaseline(options.baselinePath);
    const indexed = stage1Findings.map((finding, index) => ({
      ruleId: finding.ruleId,
      file: finding.file,
      snippet: finding.snippet,
      index,
    }));
    const filtered = filterAgainstBaseline(indexed, baseline);
    baselined = filtered.baselined;
    const keptIndexes = new Set(filtered.kept.map(entry => entry.index));
    stage1Findings = stage1Findings.filter((_, index) => keptIndexes.has(index));
    allSuspiciousKept = allSuspicious.filter((_, index) => keptIndexes.has(index));
  }

  let diffFiltered = 0;
  if (options.diffPath) {
    // Same tandem index filter as the baseline: findings outside the diff
    // never reach Stage 2, so a PR-bot scan pays LLM cost only for the
    // change under review. Finding.file is cwd-relative (see
    // createStage1Findings), matching git's repo-relative diff paths when
    // the scan runs from the repository root.
    const changed = await loadChangedLines(options.diffPath);
    const keptIndexes = new Set(
      stage1Findings
        .map((finding, index) => ({ finding, index }))
        .filter(({ finding }) => overlapsChangedLines(
          changed,
          finding.file,
          finding.location.start.line,
          finding.location.end.line,
        ))
        .map(({ index }) => index),
    );
    diffFiltered = stage1Findings.length - keptIndexes.size;
    stage1Findings = stage1Findings.filter((_, index) => keptIndexes.has(index));
    allSuspiciousKept = allSuspiciousKept.filter((_, index) => keptIndexes.has(index));
  }

  let findings = stage1Findings;
  let dismissedFindings: Finding[] = [];
  let llmCalls = 0;
  let estimatedCost = 0;
  let cacheHits = 0;

  if (!options.dryRun && allSuspiciousKept.length > 0) {
    const mergedDependencies: AnalyzeFindingsDependencies = { ...dependencies };
    if (!mergedDependencies.cache && options.config.cache.enabled) {
      mergedDependencies.cache = new FileCacheStore({
        directory: resolve(process.cwd(), options.config.cache.directory),
        ttlSeconds: options.config.cache.ttl,
      });
    }

    const analyzed = await analyzeFindings({
      findings: stage1Findings,
      suspiciousNodes: allSuspiciousKept,
      llm: options.config.llm,
      fix: options.fix,
    }, mergedDependencies);

    findings = analyzed.findings;
    dismissedFindings = analyzed.dismissed;
    llmCalls = analyzed.llmCalls;
    estimatedCost = analyzed.estimatedCost;
    cacheHits = analyzed.cacheHits;
  }

  if (options.minSeverity) {
    const minRank = SEVERITY_RANK[options.minSeverity];
    findings = findings.filter(f => SEVERITY_RANK[f.severity] >= minRank);
  }

  const result: ScanResult = {
    files: files.length,
    suspicious: allSuspicious.length,
    suppressed,
    baselined,
    diffFiltered,
    findings,
    dismissedFindings,
    skipped,
    duration: Date.now() - startTime,
    llmCalls,
    estimatedCost,
    cacheHits,
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
