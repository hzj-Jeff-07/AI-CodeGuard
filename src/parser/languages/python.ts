import type { LanguageAdapter, ASTNode, CallInfo } from '../../types/index.js';

export const pythonAdapter: LanguageAdapter = {
  language: 'python',
  fileExtensions: ['.py'],

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
