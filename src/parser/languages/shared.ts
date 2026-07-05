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
