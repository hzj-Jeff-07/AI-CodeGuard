import type { Language, LanguageAdapter, StandardNodeType, ASTNode, CallInfo } from '../../types/index.js';

const NODE_TYPE_MAP: Record<string, StandardNodeType> = {
  'call': 'function_call',
  'f_string': 'template_string',
  'binary_operator': 'binary_op',
  'assignment': 'assignment',
  'import_statement': 'import',
  'import_from_statement': 'import',
  'function_definition': 'function_def',
  'class_definition': 'class_def',
  'attribute': 'member_access',
  'identifier': 'identifier',
  'string': 'literal',
  'integer': 'literal',
};

export const pythonAdapter: LanguageAdapter = {
  language: 'python',
  fileExtensions: ['.py'],

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
