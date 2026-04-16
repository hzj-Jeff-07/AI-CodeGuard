import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const MISCONFIG_PATTERNS = [
  { pattern: /cors.*origin.*['"`]\*['"`]/i, name: 'CORS wildcard origin' },
  { pattern: /secure\s*:\s*false/i, name: 'Secure flag disabled' },
  { pattern: /httpOnly\s*:\s*false/i, name: 'HttpOnly flag disabled' },
  { pattern: /sameSite\s*:\s*['"`]none['"`]/i, name: 'SameSite=None' },
  { pattern: /helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false/i, name: 'CSP disabled' },
  { pattern: /DEBUG\s*=\s*True/i, name: 'Debug mode enabled' },
  { pattern: /verify\s*=\s*False/i, name: 'SSL verification disabled' },
  { pattern: /rejectUnauthorized\s*:\s*false/i, name: 'TLS verification disabled' },
];

export const securityMisconfiguration: BuiltInRule = {
  id: 'CG-050',
  name: 'Security Misconfiguration',
  severity: 'medium',
  category: 'config',
  languages: ['javascript', 'typescript', 'python'],
  description: 'Detects common security misconfigurations (CORS wildcard, debug mode, disabled TLS verification).',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    // Only check leaf nodes, not the root (entire file)
    if (node.rawType === 'program') return null;
    const text = node.text;

    for (const { pattern, name } of MISCONFIG_PATTERNS) {
      if (pattern.test(text)) {
        return {
          file: ctx.file,
          language: ctx.language,
          ruleId: 'CG-050',
          ruleName: 'Security Misconfiguration',
          node,
          location: node.location,
          snippet: ctx.getSnippet(node),
          context: ctx.getContext(node, 2),
          confidence: 0.7,
          metadata: { misconfiguration: name },
        };
      }
    }

    return null;
  },
};
