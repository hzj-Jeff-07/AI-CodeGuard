export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type RuleCategory = 'injection' | 'xss' | 'auth' | 'path' | 'data' | 'config' | 'ssrf';

export interface FunctionPattern {
  match: string[];
  on?: string[];
}

export interface Pattern {
  type?: string;
  function?: FunctionPattern;
  arguments?: PatternArgument[];
  operator?: string;
  hasExpressions?: boolean;
}

export interface PatternArgument {
  type: string;
  operator?: string;
  hasExpressions?: boolean;
}

export interface RuleDefinition {
  id: string;
  name: string;
  severity: Severity;
  category: RuleCategory;
  languages: string[];
  description: string;
  patterns: Pattern[];
  exclude?: Pattern[];
}

export interface CompiledRule extends RuleDefinition {
  match(node: import('./ast.js').ASTNode, context: MatchContext): boolean;
  shouldExclude(node: import('./ast.js').ASTNode, context: MatchContext): boolean;
}

export interface MatchContext {
  file: string;
  language: import('./ast.js').Language;
  getSnippet(node: import('./ast.js').ASTNode): string;
  getContext(node: import('./ast.js').ASTNode, lines: number): string;
  extractCallInfo(node: import('./ast.js').ASTNode): import('./ast.js').CallInfo | null;
}
