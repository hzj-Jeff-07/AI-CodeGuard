import type { LanguageAdapter, StandardNodeType, ASTNode, CallInfo } from '../../types/index.js';
import { findOuterArgumentsStart } from './shared.js';

const NODE_TYPE_MAP: Record<string, StandardNodeType> = {
  'method_invocation': 'function_call',
  'object_creation_expression': 'function_call',
  'binary_expression': 'binary_op',
  'assignment_expression': 'assignment',
  'variable_declarator': 'assignment',
  'import_declaration': 'import',
  'method_declaration': 'function_def',
  'constructor_declaration': 'function_def',
  'lambda_expression': 'function_def',
  'class_declaration': 'class_def',
  'field_access': 'member_access',
  'identifier': 'identifier',
  'string_literal': 'literal',
  'decimal_integer_literal': 'literal',
  'decimal_floating_point_literal': 'literal',
};

export const javaAdapter: LanguageAdapter = {
  language: 'java',
  fileExtensions: ['.java'],

  mapNodeType(rawType: string): StandardNodeType {
    return NODE_TYPE_MAP[rawType] ?? 'unknown';
  },

  extractCallInfo(node: ASTNode): CallInfo | null {
    if (node.type !== 'function_call') return null;

    const text = node.text;
    const argsStart = findOuterArgumentsStart(text);
    if (argsStart === -1) return null;

    let callee = text.slice(0, argsStart).trim();
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
