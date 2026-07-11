import type { ASTNode, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import {
  getArgumentsText,
  USER_INPUT_GO,
  USER_INPUT_JAVA,
  USER_INPUT_JS_PY,
  USER_INPUT_PHP,
} from '../../parser/languages/shared.js';

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
const HTTP_MODULES = ['axios', 'fetch', 'http', 'https', 'got', 'urllib', 'requests', 'httpx'];
// `request` (npm) and `requests` (python, when accessed through a deeper
// chain) also name HTTP clients, but they collide with the *incoming*
// request object every web handler receives — and that object's accessors
// are verb-named too (`request.headers.get(...)`, `request.args.get(...)`).
// The client libraries are used with the bare identifier as the whole
// receiver (`requests.get(url)`, `request.post(opts)`), so these two only
// count when they ARE the receiver, never as a segment of a deeper chain.
const AMBIGUOUS_HTTP_RECEIVERS = ['request', 'requests'];
// Methods that actually issue a request on an HTTP-client receiver. Gating on
// the method as well as the receiver is what separates `axios.get(url)` from
// `request.addfinalizer(...)` (pytest) or `request.server[k].log(...)`
// (fastify) — the receiver name alone is not evidence of an outgoing call.
const HTTP_VERB_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request', 'fetch',
  'send', 'open', 'urlopen', 'urlretrieve', 'stream',
  // Go's net/http exports capitalized verbs.
  'Get', 'Post', 'Head', 'PostForm', 'Do',
]);

function receiverIsHttpModule(object: string): boolean {
  if (AMBIGUOUS_HTTP_RECEIVERS.includes(object)) return true;
  return object
    .split('.')
    .some(segment => HTTP_MODULES.includes(segment.replace(/\[.*$/, '').replace(/\?$/, '').trim()));
}

// Language-specific user-input sources for the argument check; JS/Python
// share the default. Kept in shared.ts so path/redirect/SSRF stay in sync.
const USER_INPUT_BY_LANGUAGE: Partial<Record<Language, RegExp>> = {
  go: USER_INPUT_GO,
  java: USER_INPUT_JAVA,
  php: USER_INPUT_PHP,
};
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
        ? HTTP_VERB_METHODS.has(call.name) && receiverIsHttpModule(call.object)
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
    const hasUserInput = (USER_INPUT_BY_LANGUAGE[ctx.language] ?? USER_INPUT_JS_PY).test(argsText);

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
