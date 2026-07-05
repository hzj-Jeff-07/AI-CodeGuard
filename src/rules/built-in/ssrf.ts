import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// Functions that make HTTP requests when called without a receiver object.
// Bare verbs like `get`/`post` are intentionally excluded: they match Express
// route registrations (`app.get`, `router.post`) and produce false positives.
const STANDALONE_HTTP_FUNCTIONS = ['fetch', 'axios', 'request', 'urlopen', 'curl_init'];
const HTTP_MODULES = ['axios', 'fetch', 'http', 'https', 'request', 'got', 'node-fetch', 'urllib', 'requests', 'httpx'];
// Java is gated on its own allowlists: constructors (`new URL(...)`, Apache
// HttpClient request objects) plus RestTemplate/WebClient-style method names,
// which are distinctive enough to match without a receiver check.
const HTTP_CONSTRUCTORS_JAVA = ['URL', 'HttpGet', 'HttpPost', 'HttpPut', 'HttpDelete', 'HttpPatch'];
const HTTP_METHODS_JAVA = ['getForObject', 'getForEntity', 'postForObject', 'postForEntity', 'exchange'];

export const ssrf: BuiltInRule = {
  id: 'CG-060',
  name: 'Server-Side Request Forgery (SSRF)',
  severity: 'high',
  category: 'ssrf',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects HTTP requests where the URL is constructed from user input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const isHttpCall = ctx.language === 'java'
      ? (!call.object && HTTP_CONSTRUCTORS_JAVA.includes(call.name))
        || HTTP_METHODS_JAVA.includes(call.name)
        || (call.object === 'URI' && call.name === 'create')
      : call.object
        ? HTTP_MODULES.some(m => call.object!.includes(m))
        : STANDALONE_HTTP_FUNCTIONS.includes(call.name);
    if (!isHttpCall) return null;

    // Check if URL argument contains dynamic content
    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || (ctx.language === 'go' && /\bfmt\.Sprintf\s*\(/.test(call.fullExpression))
      || (ctx.language === 'java' && /\bString\.format\s*\(/.test(call.fullExpression));

    // Or if the URL references user input
    const text = call.fullExpression;
    const hasUserInput = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv|input)/.test(text);

    if (!hasDynamic && !hasUserInput) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-060',
      ruleName: 'Server-Side Request Forgery (SSRF)',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.75,
      metadata: { method: call.name, object: call.object },
    };
  },
};
