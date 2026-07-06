import type { ASTNode, Language, CallInfo, SuspiciousNode } from '../types/index.js';
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
  wasAssignedFrom(varName: string, sourcePattern: RegExp, node: ASTNode, lines?: number): boolean;
}

// Stage 1 has no real function-scope structure to trace (the parser produces
// a flat list of interesting nodes, not a nested AST — see
// docs/design/RULES.md), so this is a textual approximation: look for
// `varName = <rhs>` (or Go's `:=`) in the lines surrounding `node`, and test
// `sourcePattern` only against the right-hand side of that specific
// assignment — not the whole context window, so an unrelated occurrence of
// the pattern elsewhere nearby doesn't produce a false match.
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function createRuleContext(file: string, language: Language, source: string): RuleCheckContext {
  const adapter = getAdapter(language);
  const sourceLines = source.split('\n');

  function getContext(node: ASTNode, lines: number): string {
    const startLine = Math.max(0, node.location.start.line - 1 - lines);
    const endLine = Math.min(sourceLines.length, node.location.end.line + lines);
    return sourceLines.slice(startLine, endLine).join('\n');
  }

  return {
    file,
    language,
    source,

    getSnippet(node: ASTNode): string {
      return node.text;
    },

    getContext,

    extractCallInfo(node: ASTNode): CallInfo | null {
      return adapter.extractCallInfo(node);
    },

    wasAssignedFrom(varName: string, sourcePattern: RegExp, node: ASTNode, lines = 3): boolean {
      const context = getContext(node, lines);
      // `\b` only matches at a word/non-word transition, so it must be
      // dropped for names starting with a non-word sigil (PHP's `$var`) —
      // otherwise it never matches, since both the sigil and whatever
      // precedes it (whitespace, newline) are non-word characters.
      const prefix = /^\w/.test(varName) ? '\\b' : '';
      const assignRe = new RegExp(`${prefix}${escapeRegExp(varName)}\\s*:?=([^;\\n]*)`);
      const match = assignRe.exec(context);
      if (!match) return false;
      return sourcePattern.test(match[1]);
    },
  };
}
