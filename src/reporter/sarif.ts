import type { Finding, ScanResult, Severity } from '../types/index.js';
import { VERSION } from '../version.js';
import { cweForRule, cweHelpUri, securitySeverityScore } from '../rules/cwe.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRuleDescriptor[];
}

interface SarifRuleDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri?: string;
  properties: {
    tags: string[];
    'security-severity': string;
  };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string; markdown?: string };
  locations: SarifLocation[];
  fixes?: SarifFix[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region: {
      startLine: number;
      startColumn: number;
      endLine: number;
      endColumn: number;
      snippet?: { text: string };
    };
  };
}

interface SarifFix {
  description: { text: string };
  artifactChanges: Array<{
    artifactLocation: { uri: string };
    replacements: Array<{
      deletedRegion: { startLine: number; endLine: number };
      insertedContent: { text: string };
    }>;
  }>;
}

function severityToLevel(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
  }
}

export function formatSARIF(result: ScanResult): string {
  // Collect unique rule IDs from findings
  const ruleMap = new Map<string, Finding>();
  for (const f of result.findings) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, f);
    }
  }

  const sarifLog: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'AI-CodeGuard',
          version: VERSION,
          informationUri: 'https://github.com/hzj-Jeff-07/AI-CodeGuard',
          rules: Array.from(ruleMap.entries()).map(([id, f]) => {
            const cwe = cweForRule(id);
            const descriptor: SarifRuleDescriptor = {
              id,
              name: f.title.replace(/\s+/g, ''),
              shortDescription: { text: f.title },
              defaultConfiguration: { level: severityToLevel(f.severity) },
              properties: {
                // GitHub Code Scanning renders `external/cwe/cwe-N` tags as CWE
                // labels and ranks alerts by `security-severity`.
                tags: cwe !== undefined ? ['security', `external/cwe/cwe-${cwe}`] : ['security'],
                'security-severity': securitySeverityScore(f.severity),
              },
            };
            if (cwe !== undefined) {
              descriptor.helpUri = cweHelpUri(cwe);
            }
            return descriptor;
          }),
        },
      },
      results: result.findings.map(f => {
        const sarifResult: SarifResult = {
          ruleId: f.ruleId,
          level: severityToLevel(f.severity),
          message: {
            text: f.description,
            markdown: f.llmAnalysis
              ? `**${f.title}**\n\n${f.description}\n\nLLM Confidence: ${(f.llmAnalysis.confidence * 100).toFixed(0)}%\n\n${f.llmAnalysis.reasoning}`
              : undefined,
          },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: f.file.replace(/\\/g, '/'),
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: f.location.start.line,
                startColumn: f.location.start.column + 1,
                endLine: f.location.end.line,
                endColumn: f.location.end.column + 1,
                snippet: { text: f.snippet },
              },
            },
          }],
        };

        if (f.fix) {
          sarifResult.fixes = [{
            description: { text: f.fix.description },
            artifactChanges: [{
              artifactLocation: { uri: f.file.replace(/\\/g, '/') },
              replacements: [{
                deletedRegion: {
                  startLine: f.location.start.line,
                  endLine: f.location.end.line,
                },
                insertedContent: { text: f.fix.code },
              }],
            }],
          }];
        }

        return sarifResult;
      }),
    }],
  };

  return JSON.stringify(sarifLog, null, 2);
}
