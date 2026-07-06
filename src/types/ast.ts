export type Language = 'javascript' | 'typescript' | 'python' | 'go' | 'java' | 'php';

export interface SourceLocation {
  start: { line: number; column: number };
  end: { line: number; column: number };
}

export type StandardNodeType =
  | 'function_call'
  | 'string_concat'
  | 'template_string'
  | 'assignment'
  | 'import'
  | 'function_def'
  | 'class_def'
  | 'binary_op'
  | 'member_access'
  | 'identifier'
  | 'literal'
  | 'unknown';

export interface ASTNode {
  type: StandardNodeType;
  rawType: string;
  text: string;
  location: SourceLocation;
  children: ASTNode[];
  parent: ASTNode | null;
  fields: Record<string, ASTNode | ASTNode[] | undefined>;
}

export interface ASTree {
  root: ASTNode;
  language: Language;
  source: string;
}

export interface CallInfo {
  name: string;
  object: string | null;
  arguments: ASTNode[];
  fullExpression: string;
}

export interface LanguageAdapter {
  language: Language;
  fileExtensions: string[];
  extractCallInfo(node: ASTNode): CallInfo | null;
}
