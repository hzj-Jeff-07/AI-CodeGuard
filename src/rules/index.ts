import type { ASTNode, ASTree, SuspiciousNode } from '../types/index.js';
import { walkAST } from '../parser/ast-walker.js';
import { createRuleContext, type BuiltInRule, type RuleCheckContext } from './engine.js';
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
  const suspiciousNodes: SuspiciousNode[] = [];
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
            suspiciousNodes.push(result);
          }
        }
      }
    },
  });

  return suspiciousNodes;
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
