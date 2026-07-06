import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import { findOuterArgumentsStart } from '../../parser/languages/shared.js';

const XSS_SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'document.writeln'];

// Python: mark_safe (Django) / Markup (Flask/Jinja2's markupsafe) mark a
// string as pre-escaped HTML, and render_template_string compiles a string
// as a Jinja2 template outright — feeding any of them dynamic content
// reintroduces the escaping autoescaping is supposed to provide.
const XSS_SINK_FUNCTIONS_PY = ['mark_safe', 'Markup', 'render_template_string'];
// Java: writing straight to the response's Writer bypasses JSP/Thymeleaf's
// automatic output encoding.
const XSS_SINK_METHODS_JAVA = ['write', 'print', 'println'];

// A lone string-literal argument (or no argument at all) is inert output;
// anything else (a variable, an f-string, string concatenation, a nested
// call) means the sink is rendering something other than a fixed literal.
function hasOnlyStaticStringArg(fullExpression: string): boolean {
  const argsStart = findOuterArgumentsStart(fullExpression);
  if (argsStart === -1) return false;
  const argsText = fullExpression.slice(argsStart + 1, fullExpression.lastIndexOf(')')).trim();
  return argsText === '' || /^['"][^'"]*['"]$/.test(argsText);
}

// Catches the common two-step idiom `PrintWriter out = response.getWriter();
// out.println(...)`, not just the chained one-liner
// `response.getWriter().write(...)`.
const GET_WRITER_PATTERN = /\bgetWriter\(\)/;

export const xssReflected: BuiltInRule = {
  id: 'CG-010',
  name: 'Cross-Site Scripting (XSS)',
  severity: 'high',
  category: 'xss',
  languages: ['javascript', 'typescript', 'python', 'java'],
  description: 'Detects assignment to innerHTML or use of document.write with dynamic content.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    // Only check leaf nodes, not the root (entire file)
    if (node.rawType === 'program') return null;

    if (ctx.language === 'python' || ctx.language === 'java') {
      if (node.type !== 'function_call') return null;

      const call = ctx.extractCallInfo(node);
      if (!call) return null;

      const isSink = ctx.language === 'python'
        ? call.object === null && XSS_SINK_FUNCTIONS_PY.includes(call.name)
        : call.object !== null && XSS_SINK_METHODS_JAVA.includes(call.name)
          && (call.object.includes('getWriter')
            || ctx.wasAssignedFrom(call.object, GET_WRITER_PATTERN, node));
      if (!isSink) return null;
      if (hasOnlyStaticStringArg(call.fullExpression)) return null;

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
        metadata: { sink: ctx.language === 'python' ? call.name : `${call.object}.${call.name}` },
      };
    }

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
