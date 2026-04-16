import type { ASTNode, Language, CallInfo, SuspiciousNode, SourceLocation } from '../types/index.js';
import { getAdapter } from '../parser/index.js';

export interface BuiltInRule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  languages: Language[];
  description: string;
  check(node: ASTNode, context: RuleCheckContext): SuspiciousNode | null;
}

export interface RuleCheckContext {
  file: string;
  language: Language;
  source: string;
  getSnippet(node: ASTNode): string;
  getContext(node: ASTNode, lines: number): string;
  extractCallInfo(node: ASTNode): CallInfo | null;
}

export function createRuleContext(file: string, language: Language, source: string): RuleCheckContext {
  const adapter = getAdapter(language);
  const sourceLines = source.split('\n');

  return {
    file,
    language,
    source,

    getSnippet(node: ASTNode): string {
      return node.text;
    },

    getContext(node: ASTNode, lines: number): string {
      const startLine = Math.max(0, node.location.start.line - 1 - lines);
      const endLine = Math.min(sourceLines.length, node.location.end.line + lines);
      return sourceLines.slice(startLine, endLine).join('\n');
    },

    extractCallInfo(node: ASTNode): CallInfo | null {
      return adapter.extractCallInfo(node);
    },
  };
}
