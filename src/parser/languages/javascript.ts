import type { Language, LanguageAdapter, ASTNode, CallInfo } from '../../types/index.js';

export const javascriptAdapter: LanguageAdapter = {
  language: 'javascript',
  fileExtensions: ['.js', '.jsx', '.mjs', '.cjs'],

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
