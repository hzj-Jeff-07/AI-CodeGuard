import type { ASTNode, SuspiciousNode } from '../../types/index.js';
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
// collision risk.
const REGEX_METHODS_PY = ['compile', 'match', 'search', 'fullmatch', 'sub', 'split', 'findall', 'finditer'];
const REGEX_METHODS_GO = ['MustCompile', 'Compile', 'MatchString'];
const REGEX_FUNCTIONS_PHP = ['preg_match', 'preg_match_all', 'preg_replace', 'preg_split'];

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

    let isRegexCall: boolean;
    if (ctx.language === 'python') {
      isRegexCall = call.object === 're' && REGEX_METHODS_PY.includes(call.name);
    } else if (ctx.language === 'go') {
      isRegexCall = call.object === 'regexp' && REGEX_METHODS_GO.includes(call.name);
    } else if (ctx.language === 'java') {
      isRegexCall = call.object === 'Pattern' && call.name === 'compile';
    } else if (ctx.language === 'php') {
      isRegexCall = call.object === null && REGEX_FUNCTIONS_PHP.includes(call.name);
    } else {
      isRegexCall = call.object === null && call.name === 'RegExp';
    }
    if (!isRegexCall) return null;

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
