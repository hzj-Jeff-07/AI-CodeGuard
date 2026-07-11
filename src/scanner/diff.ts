import { readFile } from 'node:fs/promises';

// ── Diff filtering ─────────────────────────────────────────────────
//
// A PR bot that comments on every finding in a *touched file* re-litigates
// years-old code the moment someone edits one line of it — the single most
// complained-about behavior a review bot can have. `--diff <file>` restricts
// findings to lines the diff actually adds or modifies, so the bot only
// speaks about the change under review. (GITHUB_APP.md §3 specifies this
// hunk filtering; this is the CLI implementation.)

/** Changed-line sets keyed by repo-relative path (forward slashes). */
export type ChangedLines = Map<string, Set<number>>;

/**
 * Parses a unified diff (git or plain) into the set of NEW-side line numbers
 * each file adds or modifies. Deleted files (`+++ /dev/null`) contribute
 * nothing — there is no new-side line to anchor a finding to.
 */
export function parseUnifiedDiff(diffText: string): ChangedLines {
  const changed: ChangedLines = new Map();
  let currentFile: string | null = null;
  let sawFileHeader = false;
  let newLine = 0;
  // Hunk-body lines remaining on each side, from the @@ header's counts.
  // Tracking these (instead of a boolean) is what disambiguates content
  // from structure: a deleted SQL comment renders as `--- x` and an added
  // `++ i` renders as `+++ i`, which prefix-sniffing alone would misread
  // as file headers. Inside a hunk, every line is body by definition.
  let oldRemaining = 0;
  let newRemaining = 0;

  for (const line of diffText.split('\n')) {
    if (oldRemaining > 0 || newRemaining > 0) {
      if (line.startsWith('\\')) {
        // "\ No newline at end of file" — a marker, not content.
        continue;
      }
      if (line.startsWith('+')) {
        if (currentFile !== null) {
          let lines = changed.get(currentFile);
          if (!lines) {
            lines = new Set();
            changed.set(currentFile, lines);
          }
          lines.add(newLine);
        }
        newLine += 1;
        newRemaining -= 1;
      } else if (line.startsWith('-')) {
        // Deletions live on the old side only.
        oldRemaining -= 1;
      } else {
        // Context line (leading space, or empty if trailing whitespace was
        // stripped somewhere in transit) — present on both sides.
        newLine += 1;
        oldRemaining -= 1;
        newRemaining -= 1;
      }
      continue;
    }

    if (line.startsWith('+++ ')) {
      // "+++ b/src/app.ts" (git) or "+++ src/app.ts" (plain diff); a
      // trailing tab + timestamp is legal in POSIX diffs.
      const target = line.slice(4).split('\t')[0].trim();
      currentFile = target === '/dev/null' ? null : target.replace(/^b\//, '');
      sawFileHeader = true;
      continue;
    }

    const hunk = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      oldRemaining = hunk[1] === undefined ? 1 : Number(hunk[1]);
      newLine = Number(hunk[2]);
      newRemaining = hunk[3] === undefined ? 1 : Number(hunk[3]);
      continue;
    }
  }

  if (!sawFileHeader && diffText.trim() !== '') {
    // A non-diff file passed as --diff would otherwise parse to "no changed
    // lines" and silently filter out every finding — a green scan produced
    // by a typo. Refuse loudly instead.
    throw new Error('Not a unified diff: no "+++" file header found. Generate one with `git diff <base>...<head>`.');
  }

  return changed;
}

export async function loadChangedLines(path: string): Promise<ChangedLines> {
  let text: string;
  try {
    text = await readFile(path, 'utf-8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new Error(`Diff file not found: ${path}`);
    }
    throw new Error(`Cannot read diff file ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseUnifiedDiff(text);
}

/**
 * True when any line of `[startLine, endLine]` (repo-relative `file`, both
 * bounds inclusive) was added or modified by the diff. Iterates the span
 * rather than the diff's line set — finding spans are a handful of lines,
 * changed-line sets can be the whole PR.
 */
export function overlapsChangedLines(
  changed: ChangedLines,
  file: string,
  startLine: number,
  endLine: number,
): boolean {
  const lines = changed.get(file);
  if (!lines) return false;
  for (let line = startLine; line <= Math.max(startLine, endLine); line += 1) {
    if (lines.has(line)) return true;
  }
  return false;
}
