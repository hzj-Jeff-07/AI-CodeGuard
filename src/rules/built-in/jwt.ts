import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// The "none" algorithm disables JWT signature verification entirely — an
// attacker can forge any token by setting `alg: none` and stripping the
// signature. No legitimate configuration ever allows it; there is no
// lower-severity legitimate use to guard against, unlike most other
// heuristics in this file. `[^\]]*` lets `none` appear anywhere in the
// allow-list (`['HS256', 'none']` accepts it alongside a real algorithm and
// is just as exploitable), not only as the first element — bounded to the
// array's own `]` so it stays linear and can't span unrelated code.
const JWT_NONE_ALGORITHM = /algorithms\s*[:=]\s*\[[^\]]*['"]none['"]/i;
// PHP's firebase/php-jwt passes the allowed-algorithms list as a positional
// array (no `algorithms:` key), so match `'none'` inside any array literal
// that is *not* a variable subscript — the negative lookbehind excludes
// `$keys['none']` (key-id lookup) while still catching `JWT::decode(..., ['none'])`.
const JWT_NONE_ARRAY_PHP = /(?<![\w\]])\[[^\]]*['"]none['"]/i;
// PyJWT's explicit opt-outs of signature checking: the modern
// `options={'verify_signature': False}` and the legacy pre-2.0 `verify=False`
// keyword. Only meaningful on an actual decode call (see the gate below), so
// it can't be confused with e.g. requests' `verify=False` TLS-cert option.
const JWT_VERIFY_DISABLED_PY = /verify_signature['"]?\s*[:=]\s*False\b|\bverify\s*=\s*False\b/;

// The danger patterns above are only trustworthy on a genuine JWT
// verify/decode call. PHP's firebase library exposes it as static
// `JWT::decode(...)`; jsonwebtoken (JS) uses `.verify(...)`, PyJWT uses
// `.decode(...)`. Gating here removes false positives from unrelated APIs
// that happen to take an `algorithms` list containing a `'none'` enum value.
function isJwtVerifyCall(object: string | null, name: string, language: string): boolean {
  if (language === 'php') {
    return object === 'JWT' && name === 'decode';
  }
  return name === 'verify' || name === 'decode';
}

export const jwtSignatureBypass: BuiltInRule = {
  id: 'CG-026',
  name: 'JWT Signature Bypass',
  severity: 'critical',
  category: 'auth',
  languages: ['javascript', 'typescript', 'python', 'php'],
  description: 'Detects JWT verification configured to accept the "none" algorithm or with signature checking explicitly disabled, letting a forged or unsigned token be accepted as valid.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    if (!isJwtVerifyCall(call.object, call.name, ctx.language)) return null;

    const noneAlgorithmPattern = ctx.language === 'php' ? JWT_NONE_ARRAY_PHP : JWT_NONE_ALGORITHM;
    const hasNoneAlgorithm = noneAlgorithmPattern.test(call.fullExpression);
    const hasVerifyDisabled = ctx.language === 'python' && JWT_VERIFY_DISABLED_PY.test(call.fullExpression);

    if (!hasNoneAlgorithm && !hasVerifyDisabled) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-026',
      ruleName: 'JWT Signature Bypass',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.8,
      metadata: { method: call.name, object: call.object },
    };
  },
};
