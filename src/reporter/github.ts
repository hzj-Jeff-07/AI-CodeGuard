import type { Finding, ScanResult, Severity } from '../types/index.js';
import { cweLabel } from '../rules/cwe.js';

// GitHub PR review payload — the shape a bot POSTs to
// `POST /repos/{owner}/{repo}/pulls/{number}/reviews`. Each finding becomes an
// inline review comment anchored to its file + line. This is the data layer of
// a PR-review bot: the CLI produces the payload, and a thin Action step (or any
// caller with a token) submits it. Keeping it a pure reporter means it's fully
// testable offline and carries no GitHub credentials itself.
//
// GitHub only accepts review comments whose line is part of the PR diff; the
// caller is expected to have scanned the PR's changed files (or the Action
// filters by diff before submitting), so this reporter emits a comment per
// finding and leaves diff-scoping to the caller.

interface ReviewComment {
  path: string;
  line: number;
  side: 'RIGHT';
  body: string;
}

interface ReviewPayload {
  // `event: COMMENT` posts a non-blocking review; a caller wanting to block
  // the PR can rewrite this to REQUEST_CHANGES, but the default stays advisory.
  event: 'COMMENT';
  body: string;
  comments: ReviewComment[];
}

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
};

// A fenced code block whose fence is longer than any backtick run inside the
// code, so model-generated fix code that itself contains ``` can't close the
// fence early and spill raw text into the comment (CommonMark rule: an opening
// fence of N backticks is only closed by a run of >= N backticks).
function fencedBlock(code: string): string {
  const longestRun = Math.max(0, ...[...code.matchAll(/`+/g)].map(m => m[0].length));
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return `${fence}\n${code}\n${fence}`;
}

function commentBody(finding: Finding): string {
  const cwe = cweLabel(finding.ruleId);
  const header = `${SEVERITY_EMOJI[finding.severity]} **${finding.title}** \`${finding.ruleId}\`${cwe ? ` · [${cwe}](https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html)` : ''}`;
  const lines = [header, '', finding.description];

  if (finding.llmAnalysis) {
    lines.push('', `> Stage 2 (${(finding.llmAnalysis.confidence * 100).toFixed(0)}% confidence): ${finding.llmAnalysis.reasoning}`);
  }
  if (finding.fix) {
    lines.push('', '**Suggested fix:** ' + finding.fix.description, '', fencedBlock(finding.fix.code));
  }
  lines.push('', '<sub>Reported by AI-CodeGuard. Add `// codeguard-ignore ' + finding.ruleId + '` to suppress.</sub>');
  return lines.join('\n');
}

function summaryBody(result: ScanResult): string {
  if (result.findings.length === 0) {
    return '✅ **AI-CodeGuard**: no new security findings.';
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of result.findings) counts[f.severity] += 1;
  const parts = (Object.keys(counts) as Severity[])
    .filter(s => counts[s] > 0)
    .map(s => `${counts[s]} ${s}`);
  return `🛡️ **AI-CodeGuard** found ${result.findings.length} security finding(s): ${parts.join(', ')}.`;
}

export function formatGitHubReview(result: ScanResult): string {
  const payload: ReviewPayload = {
    event: 'COMMENT',
    body: summaryBody(result),
    comments: result.findings.map(finding => ({
      path: finding.file,
      line: finding.location.start.line,
      side: 'RIGHT',
      body: commentBody(finding),
    })),
  };
  return JSON.stringify(payload, null, 2);
}
