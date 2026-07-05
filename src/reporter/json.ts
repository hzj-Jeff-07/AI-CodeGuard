import type { Finding, ScanResult } from '../types/index.js';
import { VERSION } from '../version.js';

export function formatJSON(result: ScanResult): string {
  const output = {
    version: VERSION,
    scan: {
      files: result.files,
      suspicious: result.suspicious,
      duration: result.duration,
      llmCalls: result.llmCalls,
      estimatedCost: result.estimatedCost,
      cacheHits: result.cacheHits,
    },
    findings: result.findings.map(serializeFinding),
    dismissedFindings: (result.dismissedFindings ?? []).map(serializeFinding),
    skipped: result.skipped,
  };

  return JSON.stringify(output, null, 2);
}

function serializeFinding(f: Finding) {
  return {
    id: f.id,
    ruleId: f.ruleId,
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
