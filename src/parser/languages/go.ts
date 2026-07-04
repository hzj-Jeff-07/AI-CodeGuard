import type { LanguageAdapter, StandardNodeType, ASTNode, CallInfo } from '../../types/index.js';

const NODE_TYPE_MAP: Record<string, StandardNodeType> = {
  'call_expression': 'function_call',
  'binary_expression': 'binary_op',
  'assignment_statement': 'assignment',
  'short_var_declaration': 'assignment',
  'import_declaration': 'import',
  'function_declaration': 'function_def',
  'method_declaration': 'function_def',
  'func_literal': 'function_def',
  'selector_expression': 'member_access',
  'identifier': 'identifier',
  'interpreted_string_literal': 'literal',
  'raw_string_literal': 'literal',
  'int_literal': 'literal',
  'float_literal': 'literal',
};

export const goAdapter: LanguageAdapter = {
  language: 'go',
  fileExtensions: ['.go'],

  mapNodeType(rawType: string): StandardNodeType {
    return NODE_TYPE_MAP[rawType] ?? 'unknown';
  },

  extractCallInfo(node: ASTNode): CallInfo | null {
    if (node.type !== 'function_call') return null;

    const text = node.text;
    const parenIndex = text.indexOf('(');
    if (parenIndex === -1) return null;

    const callee = text.slice(0, parenIndex).trim();
    const dotIndex = callee.lastIndexOf('.');
    const name = dotIndex >= 0 ? callee.slice(dotIndex + 1) : callee;
    const object = dotIndex >= 0 ? callee.slice(0, dotIndex) : null;

    return {
      name,
      object,
      arguments: node.children,
      fullExpression: text,
    };
  },
};
