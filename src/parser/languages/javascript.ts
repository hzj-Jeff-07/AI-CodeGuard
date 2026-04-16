import type { Language, LanguageAdapter, StandardNodeType, ASTNode, CallInfo } from '../../types/index.js';

const NODE_TYPE_MAP: Record<string, StandardNodeType> = {
  'call_expression': 'function_call',
  'new_expression': 'function_call',
  'template_string': 'template_string',
  'template_literal': 'template_string',
  'binary_expression': 'binary_op',
  'assignment_expression': 'assignment',
  'variable_declarator': 'assignment',
  'import_statement': 'import',
  'import_declaration': 'import',
  'function_declaration': 'function_def',
  'arrow_function': 'function_def',
  'method_definition': 'function_def',
  'member_expression': 'member_access',
  'identifier': 'identifier',
  'string': 'literal',
  'number': 'literal',
};

export const javascriptAdapter: LanguageAdapter = {
  language: 'javascript',
  fileExtensions: ['.js', '.jsx', '.mjs', '.cjs'],

  mapNodeType(rawType: string): StandardNodeType {
    return NODE_TYPE_MAP[rawType] ?? 'unknown';
  },

  extractCallInfo(node: ASTNode): CallInfo | null {
    if (node.type !== 'function_call') return null;

    const text = node.text;
    const parenIndex = text.indexOf('(');
    if (parenIndex === -1) return null;

    let callee = text.slice(0, parenIndex).trim();
    if (callee.startsWith('new ')) {
      callee = callee.slice(4).trim();
    }
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

export const typescriptAdapter: LanguageAdapter = {
  ...javascriptAdapter,
  language: 'typescript' as Language,
  fileExtensions: ['.ts', '.tsx'],
};
