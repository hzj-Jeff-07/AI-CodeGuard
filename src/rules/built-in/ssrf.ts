import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import { getArgumentsText } from '../../parser/languages/shared.js';

// Functions that make HTTP requests when called without a receiver object.
// Bare verbs like `get`/`post` are intentionally excluded: they match Express
// route registrations (`app.get`, `router.post`) and produce false positives.
const STANDALONE_HTTP_FUNCTIONS = ['fetch', 'axios', 'request', 'urlopen', 'curl_init'];
// Receiver names that identify an HTTP client. Matched as exact dot-path
// segments (`axios.get` → `axios`, `this.http.get` → `http`), never as
// substrings: fastify/Express hand every handler an *incoming* `request`
// object, and a substring test made any `request.log.warn(...)` /
// `flask.request.get_json()` call look like an outgoing HTTP request.
// (`node-fetch` is absent because a hyphenated package name can't appear as
// an identifier — its import is called `fetch` and matches that way.)
const HTTP_MODULES = ['axios', 'fetch', 'http', 'https', 'request', 'got', 'urllib', 'requests', 'httpx'];
// Methods that actually issue a request on an HTTP-client receiver. Gating on
// the method as well as the receiver is what separates `axios.get(url)` from
// `request.addfinalizer(...)` (pytest) or `request.server[k].log(...)`
// (fastify) — the receiver name alone is not evidence of an outgoing call.
const HTTP_VERB_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request', 'fetch',
  'send', 'open', 'urlopen', 'stream',
  // Go's net/http exports capitalized verbs.
  'Get', 'Post', 'Head', 'PostForm', 'Do',
]);

function receiverIsHttpModule(object: string): boolean {
  return object
    .split('.')
    .some(segment => HTTP_MODULES.includes(segment.replace(/\[.*$/, '').trim()));
}
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
        ? receiverIsHttpModule(call.object) && HTTP_VERB_METHODS.has(call.name)
        : STANDALONE_HTTP_FUNCTIONS.includes(call.name);
    if (!isHttpCall) return null;

    // Check if URL argument contains dynamic content
    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || (ctx.language === 'go' && /\bfmt\.Sprintf\s*\(/.test(call.fullExpression))
      || (ctx.language === 'java' && /\bString\.format\s*\(/.test(call.fullExpression));

    // Or if the URL references user input. Tested against the argument list
    // only — testing the whole expression made the receiver match itself
    // (`request.get(...)` contains `request.` by construction).
    const argsText = getArgumentsText(call.fullExpression) ?? call.fullExpression;
    const hasUserInput = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv|input)/.test(argsText);

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
