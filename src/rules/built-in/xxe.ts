import type { ASTNode, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

// XXE is usually a matter of the *absence* of a hardening call, which Stage 1's
// flat node model can't observe. Instead each pattern below is an explicit
// opt-in to dangerous behavior — a flag or setting that a developer had to
// write deliberately and that has no safe purpose — so matching it positively
// keeps false positives low.
//
// - Python (lxml): `resolve_entities=True` substitutes external entities;
//   `no_network=False` lets the parser fetch remote DTDs.
// - Java (JAXP/SAX): `setExpandEntityReferences(true)` and enabling the
//   `load-external-dtd` / `external-general-entities` /
//   `external-parameter-entities` features (the safe direction is setting
//   these to `false`, or `disallow-doctype-decl` to `true`, neither of
//   which this pattern matches).
// - PHP (libxml): the `LIBXML_NOENT` flag substitutes entities;
//   `libxml_disable_entity_loader(false)` re-enables the external entity
//   loader that older PHP disabled as a mitigation.
// - JS/TS (libxmljs): the `noent: true` parse option substitutes entities.
const XXE_PATTERNS: Partial<Record<Language, RegExp>> = {
  python: /\bresolve_entities\s*=\s*True\b|\bno_network\s*=\s*False\b/,
  java: /setExpandEntityReferences\s*\(\s*true|(?:load-external-dtd|external-general-entities|external-parameter-entities)['"]\s*,\s*true/i,
  php: /\bLIBXML_NOENT\b|libxml_disable_entity_loader\s*\(\s*false/i,
};
// JS/TS share the default (libxmljs's `noent` parse option).
const DEFAULT_XXE_PATTERN = /\bnoent\s*:\s*true\b/i;

export const xxe: BuiltInRule = {
  id: 'CG-070',
  name: 'XML External Entity (XXE)',
  severity: 'high',
  category: 'xxe',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  description: 'Detects XML parsing configured to resolve external entities or load external DTDs, allowing file disclosure, SSRF, or denial of service via a crafted XML document.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const pattern = XXE_PATTERNS[ctx.language] ?? DEFAULT_XXE_PATTERN;
    if (!pattern.test(call.fullExpression)) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-070',
      ruleName: 'XML External Entity (XXE)',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.75,
      metadata: { method: call.name, object: call.object },
    };
  },
};
