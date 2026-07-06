// Shared across language adapters whose call syntax uses C-style trailing
// parens for arguments (Java, PHP): chained calls like
// `Runtime.getRuntime().exec(...)` or `$conn->prepare($sql)->execute()` mean
// the first '(' in the text is not the outer call's own argument list.
// Match the trailing ')' backwards instead to find the true outer call.
export function findOuterArgumentsStart(text: string): number {
  if (!text.endsWith(')')) {
    return text.indexOf('(');
  }

  let depth = 0;
  for (let i = text.length - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === ')') depth += 1;
    else if (ch === '(') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return text.indexOf('(');
}

// Returns the text between a call's own outer parentheses (its argument
// list), trimmed, or null if there is no argument list. Centralizes the
// `findOuterArgumentsStart` + slice-to-last-`)` step that several rules need
// before inspecting arguments, so the backward paren-matching lives in one
// place instead of being re-derived per rule.
export function getArgumentsText(fullExpression: string): string | null {
  const argsStart = findOuterArgumentsStart(fullExpression);
  if (argsStart === -1) return null;
  return fullExpression.slice(argsStart + 1, fullExpression.lastIndexOf(')')).trim();
}

// Splits a call's argument-list text on top-level commas only, respecting
// nested (), [], {} and quoted strings — a naive `split(',')` breaks on an
// object/array literal argument that contains its own commas, e.g. the
// second argument of `updateOne({_id: 1, active: true}, req.body)`.
export function splitTopLevelArgs(argsText: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';

  for (let i = 0; i < argsText.length; i++) {
    const ch = argsText[i];

    if (quote) {
      current += ch;
      if (ch === '\\') {
        i += 1;
        if (i < argsText.length) current += argsText[i];
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '"' || ch === '\'' || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }

    if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      current += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      current += ch;
      continue;
    }

    if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.trim() !== '' || parts.length > 0) {
    parts.push(current.trim());
  }

  return parts;
}

// An `object`/receiver extracted by backward paren-matching is only a
// meaningful identifier/member-access chain if it starts with a valid
// identifier character. A regex, string, array, or object literal directly
// followed by a call (`/foo/.test(x)`, `"a,b".join(y)`, `[1,2].join()`)
// produces a receiver text that isn't one, and must not be treated as one —
// rules pattern-match `object` against known names, so a leftover literal
// containing an unrelated keyword substring (e.g. "request" inside a regex
// pattern) would otherwise look like a plausible false match.
export function looksLikeReceiverExpression(object: string): boolean {
  return /^[A-Za-z_$]/.test(object);
}

// Known sources of externally-controlled input, shared by rules that need to
// spot user input reaching a sensitive sink (path traversal, open redirect,
// SSRF). `argv[` requires index access (`argv[2]`) rather than a bare `argv`
// identifier, which could just as easily be a fully-trusted local variable.
export const USER_INPUT_JS_PY = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv\[|process\.argv)/;
export const USER_INPUT_GO = /\b(r\.URL\.Query|r\.FormValue|r\.PostFormValue|mux\.Vars|c\.Param|c\.Query|os\.Args)\b/;
export const USER_INPUT_JAVA = /\b(getParameter|getHeader|getQueryString)\b/;
export const USER_INPUT_PHP = /\$_(GET|POST|REQUEST|COOKIE)\b/;
