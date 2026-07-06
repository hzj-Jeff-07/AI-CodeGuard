import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// The "none" algorithm disables JWT signature verification entirely — an
// attacker can forge any token by setting `alg: none` and stripping the
// signature. No legitimate configuration ever allows it; there is no
// lower-severity legitimate use to guard against, unlike most other
// heuristics in this file.
const JWT_NONE_ALGORITHM = /algorithms\s*[:=]\s*\[\s*['"]none['"]/i;
// PyJWT's explicit, unambiguous opt-out of signature checking.
const JWT_VERIFY_DISABLED_PY = /verify_signature['"]?\s*[:=]\s*False\b/;

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

    // firebase/php-jwt's `JWT::decode($jwt, $key, ['none'])` takes the
    // allowed-algorithms list as a positional array, not a named
    // `algorithms:`/`algorithms=` option, so it needs its own check gated to
    // the actual decode call (a bare `'none'` string elsewhere would be too
    // generic to trust on its own).
    const isPhpJwtDecode = ctx.language === 'php' && call.object === 'JWT' && call.name === 'decode';
    const hasNoneAlgorithm = JWT_NONE_ALGORITHM.test(call.fullExpression)
      || (isPhpJwtDecode && /['"]none['"]/i.test(call.fullExpression));
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
