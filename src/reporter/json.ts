import type { Finding, ScanResult, Severity } from '../types/index.js';
import { VERSION } from '../version.js';
import { cweForRule, cweHelpUri, cweLabel } from '../rules/cwe.js';

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

export function formatJSON(result: ScanResult): string {
  const output = {
    version: VERSION,
    scan: {
      files: result.files,
      suspicious: result.suspicious,
      suppressed: result.suppressed,
      duration: result.duration,
      llmCalls: result.llmCalls,
      estimatedCost: result.estimatedCost,
      cacheHits: result.cacheHits,
      totalFindings: result.findings.length,
      severityCounts: countBySeverity(result.findings),
    },
    findings: result.findings.map(serializeFinding),
    dismissedFindings: (result.dismissedFindings ?? []).map(serializeFinding),
    skipped: result.skipped,
  };

  return JSON.stringify(output, null, 2);
}

function serializeFinding(f: Finding) {
  const cwe = cweForRule(f.ruleId);
  return {
    id: f.id,
    ruleId: f.ruleId,
    cwe: cweLabel(f.ruleId),
    cweUri: cwe !== undefined ? cweHelpUri(cwe) : null,
    severity: f.severity,
    title: f.title,
    description: f.description,
    file: f.file,
    location: f.location,
    snippet: f.snippet,
    fix: f.fix ?? null,
    llmAnalysis: f.llmAnalysis ?? null,
  };
}
