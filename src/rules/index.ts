import type { ASTNode, ASTree, SourceLocation, SuspiciousNode } from '../types/index.js';
import { walkAST } from '../parser/ast-walker.js';
import { createRuleContext, type BuiltInRule } from './engine.js';
import * as builtInRules from './built-in/index.js';
import { loadCustomRules } from './custom.js';

export { type BuiltInRule, type RuleCheckContext, createRuleContext } from './engine.js';

const ALL_RULES: BuiltInRule[] = Object.values(builtInRules);

export function getRules(options?: {
  preset?: string;
  disable?: string[];
}): BuiltInRule[] {
  let rules = [...ALL_RULES];

  if (options?.preset === 'none') {
    return [];
  }

  if (options?.disable?.length) {
    rules = applyDisableFilter(rules, options.disable);
  }

  return rules;
}

export async function loadRules(options?: {
  preset?: string;
  custom?: string;
  disable?: string[];
}): Promise<BuiltInRule[]> {
  const builtIn = getRules({ preset: options?.preset });
  const customRules = await loadCustomRules(options?.custom, getAllRuleIds());
  const merged = [...builtIn, ...customRules];

  if (options?.disable?.length) {
    return applyDisableFilter(merged, options.disable);
  }

  return merged;
}

export function runRules(
  tree: ASTree,
  rules: BuiltInRule[],
  file: string,
): SuspiciousNode[] {
  const ctx = createRuleContext(file, tree.language, tree.source);
  const rawResults: SuspiciousNode[] = [];
  const seenLocations = new Set<string>();

  const applicableRules = rules.filter(r =>
    r.languages.includes(tree.language)
  );

  walkAST(tree.root, {
    enter(node: ASTNode) {
      for (const rule of applicableRules) {
        const result = rule.check(node, ctx);
        if (result) {
          const key = `${result.ruleId}:${result.location.start.line}:${result.location.start.column}`;
          if (!seenLocations.has(key)) {
            seenLocations.add(key);
            rawResults.push(result);
          }
        }
      }
    },
  });

  return suppressNestedDuplicates(rawResults);
}

// Stage 1 has no dataflow analysis, so a single rule can independently flag
// both an outer call and a call nested inside it for the same underlying
// issue — e.g. Go/Java's SQL-injection rule flags both `db.Query(...)` and
// the `fmt.Sprintf(...)` nested inside it, since Sprintf/String.format
// assembling SQL is also treated as suspicious on its own (needed to catch
// the two-step `query := fmt.Sprintf(...); db.Query(query)` pattern). When
// the same rule fires on a span fully contained within another of its own
// matches in the same file, keep only the outer, more-contextual finding.
function suppressNestedDuplicates(results: SuspiciousNode[]): SuspiciousNode[] {
  return results.filter(candidate => !results.some(other =>
    other !== candidate
    && other.ruleId === candidate.ruleId
    && strictlyContains(other.location, candidate.location)
  ));
}

function strictlyContains(outer: SourceLocation, inner: SourceLocation): boolean {
  const startsBefore = outer.start.line < inner.start.line
    || (outer.start.line === inner.start.line && outer.start.column <= inner.start.column);
  const endsAfter = outer.end.line > inner.end.line
    || (outer.end.line === inner.end.line && outer.end.column >= inner.end.column);
  const isSmallerSpan = outer.start.line !== inner.start.line
    || outer.start.column !== inner.start.column
    || outer.end.line !== inner.end.line
    || outer.end.column !== inner.end.column;

  return startsBefore && endsAfter && isSmallerSpan;
}

export function getAllRuleIds(): string[] {
  return ALL_RULES.map(r => r.id);
}

export function getRuleById(id: string): BuiltInRule | undefined {
  return ALL_RULES.find(r => r.id === id);
}

function applyDisableFilter(rules: BuiltInRule[], disable: string[]): BuiltInRule[] {
  return rules.filter(rule => !disable.includes(rule.id));
}
