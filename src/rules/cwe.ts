import type { Severity } from '../types/index.js';

// Primary CWE for each built-in rule. Emitted in SARIF as
// `external/cwe/cwe-N` tags (plus a MITRE `helpUri`), which GitHub Code
// Scanning and other SARIF consumers surface as CWE labels on each alert.
// A guard test asserts every built-in rule ID has an entry here, so a new
// rule can't ship without a CWE mapping.
export const CWE_BY_RULE: Record<string, number> = {
  'CG-001': 89,   // SQL Injection
  'CG-002': 78,   // OS Command Injection
  'CG-003': 95,   // Eval Injection
  'CG-010': 79,   // Cross-site Scripting
  'CG-011': 79,   // DOM-based XSS
  'CG-020': 798,  // Use of Hard-coded Credentials
  'CG-021': 327,  // Use of a Broken or Risky Cryptographic Algorithm
  'CG-022': 330,  // Use of Insufficiently Random Values
  'CG-023': 1333, // Inefficient Regular Expression Complexity (ReDoS)
  'CG-024': 943,  // Improper Neutralization of Special Elements in a Data Query (NoSQL)
  'CG-025': 601,  // URL Redirection to Untrusted Site (Open Redirect)
  'CG-026': 347,  // Improper Verification of Cryptographic Signature
  'CG-030': 22,   // Improper Limitation of a Pathname (Path Traversal)
  'CG-031': 73,   // External Control of File Name or Path
  'CG-040': 532,  // Insertion of Sensitive Information into Log File
  'CG-041': 502,  // Deserialization of Untrusted Data
  'CG-050': 693,  // Protection Mechanism Failure (security misconfiguration)
  'CG-060': 918,  // Server-Side Request Forgery
  'CG-070': 611,  // Improper Restriction of XML External Entity Reference
};

export function cweForRule(ruleId: string): number | undefined {
  return CWE_BY_RULE[ruleId];
}

// Human-readable `CWE-89` label for a rule, or null if it has no mapping
// (e.g. a custom rule). Shared by the JSON and text reporters.
export function cweLabel(ruleId: string): string | null {
  const cwe = CWE_BY_RULE[ruleId];
  return cwe !== undefined ? `CWE-${cwe}` : null;
}

export function cweHelpUri(cwe: number): string {
  return `https://cwe.mitre.org/data/definitions/${cwe}.html`;
}

// GitHub Code Scanning ranks alerts by the numeric `security-severity`
// property (CVSS-like buckets: ≥9 critical, 7–8.9 high, 4–6.9 medium,
// 0.1–3.9 low). Map our coarse severity onto the bottom of each band.
export function securitySeverityScore(severity: Severity): string {
  switch (severity) {
    case 'critical': return '9.0';
    case 'high': return '7.0';
    case 'medium': return '4.0';
    case 'low': return '2.0';
  }
}
