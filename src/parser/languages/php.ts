import type { LanguageAdapter, ASTNode, CallInfo } from '../../types/index.js';
import { findOuterArgumentsStart } from './shared.js';

export const phpAdapter: LanguageAdapter = {
  language: 'php',
  fileExtensions: ['.php'],

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
