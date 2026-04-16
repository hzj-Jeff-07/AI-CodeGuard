import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const XSS_SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'document.writeln'];

export const xssReflected: BuiltInRule = {
  id: 'CG-010',
  name: 'Cross-Site Scripting (XSS)',
  severity: 'high',
  category: 'xss',
  languages: ['javascript', 'typescript'],
  description: 'Detects assignment to innerHTML or use of document.write with dynamic content.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    // Only check leaf nodes, not the root (entire file)
    if (node.rawType === 'program') return null;
    const text = node.text;

    // Check innerHTML/outerHTML assignments
    for (const sink of XSS_SINKS) {
      if (text.includes(sink)) {
        return {
          file: ctx.file,
          language: ctx.language,
          ruleId: 'CG-010',
          ruleName: 'Cross-Site Scripting (XSS)',
          node,
          location: node.location,
          snippet: ctx.getSnippet(node),
          context: ctx.getContext(node, 3),
          confidence: 0.75,
          metadata: { sink },
        };
      }
    }

    return null;
  },
};

const DOM_XSS_SOURCES = ['location.hash', 'location.search', 'location.href', 'document.URL',
  'document.referrer', 'window.name', 'document.cookie'];

export const xssDom: BuiltInRule = {
  id: 'CG-011',
  name: 'DOM-based XSS',
  severity: 'high',
  category: 'xss',
  languages: ['javascript', 'typescript'],
  description: 'Detects DOM-based XSS where user-controlled DOM sources flow into sinks.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    // Only check leaf nodes, not the root (entire file)
    if (node.rawType === 'program') return null;
    const text = node.text;

    const hasSource = DOM_XSS_SOURCES.some(s => text.includes(s));
    const hasSink = XSS_SINKS.some(s => text.includes(s));

    if (hasSource && hasSink) {
      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-011',
        ruleName: 'DOM-based XSS',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.85,
        metadata: {},
      };
    }

    return null;
  },
};
