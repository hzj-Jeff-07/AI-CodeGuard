import type { SuspiciousNode } from '../types/index.js';

// Inline suppression directives, written in a comment (any language's comment
// syntax works — the whole line is scanned):
//
//   dangerous(userInput);            // codeguard-ignore
//   dangerous(userInput);            // codeguard-ignore CG-002 — reviewed, input is constant
//   // codeguard-ignore-next-line CG-002
//   dangerous(userInput);
//
// A bare directive suppresses every rule for the target line; a directive
// followed by a comma/space-separated rule-ID list suppresses only those
// rules. Any trailing prose (a reason) after the IDs is ignored.
//
// `codeguard-ignore` targets its own line; `codeguard-ignore-next-line`
// targets the following line. The negative lookahead keeps a same-line match
// from also firing on a `-next-line` directive that happens to sit on a line
// that itself has a finding.
const RULE_LIST = '(?:\\s+([A-Za-z]+-\\d+(?:[\\s,]+[A-Za-z]+-\\d+)*))?';
const SAME_LINE_DIRECTIVE = new RegExp(`codeguard-ignore(?!-next-line)${RULE_LIST}`);
const NEXT_LINE_DIRECTIVE = new RegExp(`codeguard-ignore-next-line${RULE_LIST}`);

interface Suppression {
  all: boolean;
  ruleIds: Set<string>;
}

function parse(line: string | undefined, directive: RegExp): Suppression | null {
  if (line === undefined) return null;
  const match = directive.exec(line);
  if (!match) return null;
  const list = match[1];
  if (!list) return { all: true, ruleIds: new Set() };
  const ruleIds = new Set(list.split(/[\s,]+/).filter(Boolean).map(id => id.toUpperCase()));
  return { all: false, ruleIds };
}

function suppresses(suppression: Suppression, ruleId: string): boolean {
  return suppression.all || suppression.ruleIds.has(ruleId.toUpperCase());
}

/**
 * Drops findings whose flagged line carries a `codeguard-ignore` directive, or
 * whose preceding line carries a `codeguard-ignore-next-line` directive,
 * covering that finding's rule. Runs per file at Stage 1 so a suppressed
 * finding never reaches Stage 2 (no wasted LLM calls).
 */
export function filterSuppressed(nodes: SuspiciousNode[], source: string): SuspiciousNode[] {
  const lines = source.split('\n');
  return nodes.filter(node => {
    const lineNo = node.location.start.line; // 1-based
    const sameLine = parse(lines[lineNo - 1], SAME_LINE_DIRECTIVE);
    if (sameLine && suppresses(sameLine, node.ruleId)) return false;
    const prevLine = lineNo >= 2 ? parse(lines[lineNo - 2], NEXT_LINE_DIRECTIVE) : null;
    if (prevLine && suppresses(prevLine, node.ruleId)) return false;
    return true;
  });
}
