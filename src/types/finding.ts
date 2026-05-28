import type { Severity } from './rule.js';
import type { Language, SourceLocation, ASTNode } from './ast.js';

export interface SuspiciousNode {
  file: string;
  language: Language;
  ruleId: string;
  ruleName: string;
  node: ASTNode;
  location: SourceLocation;
  snippet: string;
  context: string;
  confidence: number;
  metadata: Record<string, unknown>;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  location: SourceLocation;
  snippet: string;
  fix?: FixSuggestion;
  llmAnalysis?: LLMAnalysis;
}

export interface FixSuggestion {
  description: string;
  code: string;
}

export interface LLMAnalysis {
  confirmed: boolean;
  confidence: number;
  reasoning: string;
}

export interface ScanResult {
  files: number;
  suspicious: number;
  findings: Finding[];
  skipped: SkippedFile[];
  duration: number;
  llmCalls: number;
  estimatedCost: number;
  cacheHits: number;
}

export interface SkippedFile {
  file: string;
  reason: string;
}
