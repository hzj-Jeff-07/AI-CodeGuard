import type { Language, LanguageAdapter, ASTNode, CallInfo } from '../../types/index.js';
import { findOuterArgumentsStart, looksLikeReceiverExpression } from './shared.js';

export const javascriptAdapter: LanguageAdapter = {
  language: 'javascript',
  fileExtensions: ['.js', '.jsx', '.mjs', '.cjs'],

  extractCallInfo(node: ASTNode): CallInfo | null {
    if (node.type !== 'function_call') return null;

    const text = node.text;
    // Backward paren-matching handles chained calls like
    // `res.status(302).redirect(url)`, where the first '(' in the text
    // belongs to `.status(...)`, not the outer call itself.
    const parenIndex = findOuterArgumentsStart(text);
    if (parenIndex === -1) return null;

    let callee = text.slice(0, parenIndex).trim();
    if (callee.startsWith('new ')) {
      callee = callee.slice(4).trim();
    }
    const dotIndex = callee.lastIndexOf('.');
    const name = dotIndex >= 0 ? callee.slice(dotIndex + 1) : callee;
    const rawObject = dotIndex >= 0 ? callee.slice(0, dotIndex) : null;
    // A regex/string/array/object literal immediately followed by a method
    // call (e.g. `/foo/.test(x)`, `[1,2].join()`) is not a meaningful
    // receiver name for rules that pattern-match `object` — treat it as none.
    const object = rawObject !== null && looksLikeReceiverExpression(rawObject) ? rawObject : null;

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
