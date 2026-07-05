import type { LanguageAdapter, StandardNodeType, ASTNode, CallInfo } from '../../types/index.js';

const NODE_TYPE_MAP: Record<string, StandardNodeType> = {
  'function_call_expression': 'function_call',
  'member_call_expression': 'function_call',
  'nullsafe_member_call_expression': 'function_call',
  'scoped_call_expression': 'function_call',
  'object_creation_expression': 'function_call',
  'binary_expression': 'binary_op',
  'assignment_expression': 'assignment',
  'namespace_use_declaration': 'import',
  'function_definition': 'function_def',
  'method_declaration': 'function_def',
  'class_declaration': 'class_def',
  'member_access_expression': 'member_access',
  'nullsafe_member_access_expression': 'member_access',
  'variable_name': 'identifier',
  'name': 'identifier',
  'string': 'literal',
  'encapsed_string': 'literal',
  'integer': 'literal',
};

export const phpAdapter: LanguageAdapter = {
  language: 'php',
  fileExtensions: ['.php'],

  mapNodeType(rawType: string): StandardNodeType {
    return NODE_TYPE_MAP[rawType] ?? 'unknown';
  },

  extractCallInfo(node: ASTNode): CallInfo | null {
    if (node.type !== 'function_call') return null;

    const text = node.text;
    const argsStart = findOuterArgumentsStart(text);
    if (argsStart === -1) return null;

    const callee = text.slice(0, argsStart).trim();
    // `->` for method calls (nullsafe `?->` also ends in `->`, so this
    // splits it too — the leading `?` just stays attached to `object`,
    // which is harmless since rules only substring-match `object`) and
    // `::` for static calls; a bare callee is a plain function call.
    const arrowIndex = callee.lastIndexOf('->');
    const scopeIndex = callee.lastIndexOf('::');
    const sepIndex = Math.max(arrowIndex, scopeIndex);

    if (sepIndex === -1) {
      return {
        name: callee,
        object: null,
        arguments: node.children,
        fullExpression: text,
      };
    }

    const object = callee.slice(0, sepIndex);
    const name = callee.slice(sepIndex + 2);

    return {
      name,
      object,
      arguments: node.children,
      fullExpression: text,
    };
  },
};

// Chained calls like `$conn->prepare($sql)->execute()` mean the first '('
// is not the outer call's argument list. Match the trailing ')' backwards.
function findOuterArgumentsStart(text: string): number {
  if (!text.endsWith(')')) {
    return text.indexOf('(');
  }

  let depth = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === ')') depth += 1;
    else if (ch === '(') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return text.indexOf('(');
}
