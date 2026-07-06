import type { LanguageAdapter, ASTNode, CallInfo } from '../../types/index.js';
import { findOuterArgumentsStart } from './shared.js';

export const javaAdapter: LanguageAdapter = {
  language: 'java',
  fileExtensions: ['.java'],

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
