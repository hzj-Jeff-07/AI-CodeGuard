import type { ASTNode, CallInfo, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import { findOuterArgumentsStart } from '../../parser/languages/shared.js';

// Nested/overlapping quantifiers are the classic catastrophic-backtracking
// shape: a repeated group whose own content is itself repeatable, e.g.
// `(a+)+`, `(a*)*`, `(x+)*` — a backtracking engine trying to match a
// failing suffix can re-derive the same match exponentially many ways.
// This is a syntactic heuristic on the regex pattern text (one very common
// real-world shape), not a full NFA/backtracking-complexity analysis.
const CATASTROPHIC_BACKTRACKING = /\([^()]*[+*][^()]*\)[+*]/;

// Python's `re` module and Java's `Pattern` are gated on their receiver,
// since bare names like `match`/`search`/`split`/`compile` are common,
// unrelated method names on other objects (e.g. String.split()). PHP's
// `preg_*` functions and Go's `regexp` package functions have no such
// collision risk. Keyed by language so adding a new one is a single map
// entry instead of another branch in an if/else chain.
const REGEX_CALL_MATCHERS: Partial<Record<Language, (call: CallInfo) => boolean>> = {
  python: call => call.object === 're'
    && ['compile', 'match', 'search', 'fullmatch', 'sub', 'split', 'findall', 'finditer'].includes(call.name),
  go: call => call.object === 'regexp' && ['MustCompile', 'Compile', 'MatchString'].includes(call.name),
  java: call => call.object === 'Pattern' && call.name === 'compile',
  php: call => call.object === null
    && ['preg_match', 'preg_match_all', 'preg_replace', 'preg_split'].includes(call.name),
};
const DEFAULT_REGEX_CALL_MATCHER = (call: CallInfo): boolean => call.object === null && call.name === 'RegExp';

function extractArgsText(fullExpression: string): string | null {
  const argsStart = findOuterArgumentsStart(fullExpression);
  if (argsStart === -1) return null;
  return fullExpression.slice(argsStart + 1, fullExpression.lastIndexOf(')'));
}

export const insecureRegex: BuiltInRule = {
  id: 'CG-023',
  name: 'Insecure Regular Expression (ReDoS)',
  severity: 'medium',
  category: 'other',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects regular expressions with nested or overlapping quantifiers vulnerable to catastrophic backtracking (ReDoS).',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const matcher = REGEX_CALL_MATCHERS[ctx.language] ?? DEFAULT_REGEX_CALL_MATCHER;
    if (!matcher(call)) return null;

    const argsText = extractArgsText(call.fullExpression);
    if (!argsText || !CATASTROPHIC_BACKTRACKING.test(argsText)) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-023',
      ruleName: 'Insecure Regular Expression (ReDoS)',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 2),
      confidence: 0.7,
      metadata: { method: call.name },
    };
  },
};
