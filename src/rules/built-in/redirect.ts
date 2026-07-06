import type { ASTNode, CallInfo, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// A redirect target built from unvalidated user input lets an attacker send
// victims to an arbitrary external site (phishing) — the classic abuse is a
// link to the trusted domain's own redirect endpoint with the attacker's
// site as the destination parameter.
const USER_INPUT_JS_PY = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv)/;
const USER_INPUT_JAVA = /\b(getParameter|getHeader|getQueryString)\b/;
const USER_INPUT_GO = /\b(r\.URL\.Query|r\.FormValue|r\.PostFormValue|mux\.Vars|c\.Param|c\.Query)\b/;
const USER_INPUT_PHP = /\$_(GET|POST|REQUEST)\b/;

// Flask's redirect() / Django's HttpResponseRedirect / HttpResponsePermanentRedirect are bare functions.
const REDIRECT_FUNCTIONS_PY = ['redirect', 'HttpResponseRedirect', 'HttpResponsePermanentRedirect'];
// Express/Koa/Fastify all expose `.redirect(...)` on the response-like object.
const REDIRECT_OBJECTS_JS = ['res', 'response', 'reply', 'ctx'];

interface RedirectConfig {
  isRedirectCall: (call: CallInfo) => boolean;
  userInputPattern: RegExp;
}

// Each language's redirect-call matcher, keyed by language so adding a new
// one is a single map entry instead of another branch in an if/else chain.
const REDIRECT_CONFIG: Partial<Record<Language, RedirectConfig>> = {
  python: {
    isRedirectCall: call => call.object === null && REDIRECT_FUNCTIONS_PY.includes(call.name),
    userInputPattern: USER_INPUT_JS_PY,
  },
  go: {
    isRedirectCall: call => call.object === 'http' && call.name === 'Redirect',
    userInputPattern: USER_INPUT_GO,
  },
  java: {
    // The method name alone is an unambiguous signal — no unrelated Java
    // API shares it — so no receiver check is needed.
    isRedirectCall: call => call.name === 'sendRedirect',
    userInputPattern: USER_INPUT_JAVA,
  },
  php: {
    // `header()` is used for far more than redirects, so require the
    // argument to actually set a Location header.
    isRedirectCall: call => call.object === null && call.name === 'header'
      && /Location\s*:/i.test(call.fullExpression),
    userInputPattern: USER_INPUT_PHP,
  },
};
const DEFAULT_REDIRECT_CONFIG: RedirectConfig = {
  isRedirectCall: call => call.object !== null
    && REDIRECT_OBJECTS_JS.some(o => call.object!.toLowerCase() === o)
    && call.name === 'redirect',
  userInputPattern: USER_INPUT_JS_PY,
};

export const openRedirect: BuiltInRule = {
  id: 'CG-025',
  name: 'Open Redirect',
  severity: 'medium',
  category: 'other',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects HTTP redirects to a URL built from unvalidated user input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const config = REDIRECT_CONFIG[ctx.language] ?? DEFAULT_REDIRECT_CONFIG;
    if (!config.isRedirectCall(call)) return null;
    if (!config.userInputPattern.test(call.fullExpression)) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-025',
      ruleName: 'Open Redirect',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.7,
      metadata: { method: call.name },
    };
  },
};
