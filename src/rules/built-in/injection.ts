import type { ASTNode, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import { getArgumentsText, splitTopLevelArgs } from '../../parser/languages/shared.js';

const SQL_METHODS = ['query', 'execute', 'raw', 'exec', 'prepare'];
const SQL_METHODS_GO = ['Query', 'QueryRow', 'QueryContext', 'QueryRowContext', 'Exec', 'ExecContext', 'Prepare', 'PrepareContext'];
const SQL_METHODS_JAVA = ['executeQuery', 'executeUpdate', 'execute', 'prepareStatement', 'prepareCall', 'createQuery', 'createNativeQuery', 'queryForObject', 'queryForList', 'update'];
const SQL_OBJECTS = ['db', 'database', 'connection', 'conn', 'pool', 'client', 'knex', 'sequelize', 'prisma'];
const SQL_OBJECTS_GO = ['db', 'database', 'conn', 'pool', 'tx', 'stmt'];
const SQL_OBJECTS_JAVA = ['stmt', 'statement', 'conn', 'connection', 'db', 'jdbc', 'em', 'entitymanager', 'session', 'template'];
// PHP has no receiver for its core mysqli_*/pg_* functions (globals, not
// methods), so those are matched by name alone; OOP drivers (PDO, mysqli
// objects, Laravel's DB facade) are matched like the other languages.
const SQL_FUNCTIONS_PHP = ['mysqli_query', 'mysqli_real_query', 'mysqli_multi_query', 'pg_query', 'sqlite_query'];
const SQL_METHODS_PHP = ['query', 'exec', 'prepare', 'real_query', 'multi_query'];
const SQL_OBJECTS_PHP = ['db', 'database', 'conn', 'connection', 'pdo', 'mysqli', 'link'];
const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|WHERE|FROM|JOIN)\b/i;

// Replaces every string literal with a single placeholder character (U+FFFF,
// a noncharacter that can't appear in real source) so callers can reason
// about the text *between* literals without being fooled by their contents — a `%` inside
// `"... LIKE '%admin%'"` is SQL wildcard text, not a format operator, and
// identifier characters inside a literal are not a spliced-in expression.
// The placeholder keeps "a literal sits here" visible, so `\uFFFF % x`
// still reads as "format operator applied to a string literal".
const STRING_LITERAL = /'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`[^`]*`/g;
function stripStringLiterals(text: string): string {
  return text.replace(STRING_LITERAL, '\uFFFF');
}

// A string_concat whose pieces are all literals ("SELECT ..." + " FROM ...")
// is just a multi-line way of writing a constant — only concatenation that
// splices in a non-literal expression is dynamic.
function concatHasDynamicPart(text: string): boolean {
  return /[\w$]/.test(stripStringLiterals(text));
}

// JS/TS template literals parse as template_string even without an
// interpolation slot (`SELECT 1` is a constant); Python f-strings and PHP
// encapsed strings only reach the parser's template_string type when they
// actually interpolate, so they are dynamic by construction.
function isDynamicSqlFragment(c: ASTNode, language: Language): boolean {
  if (c.type === 'template_string') {
    return language === 'javascript' || language === 'typescript'
      ? c.text.includes('${')
      : true;
  }
  if (c.type === 'string_concat') return concatHasDynamicPart(c.text);
  return false;
}

export const sqlInjection: BuiltInRule = {
  id: 'CG-001',
  name: 'SQL Injection',
  severity: 'critical',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects unparameterized SQL queries built with string concatenation, template literals, fmt.Sprintf, or String.format.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    // fmt.Sprintf / String.format assembling a SQL string is suspicious on
    // its own — Stage 1 has no dataflow, so the later query(variable) call
    // is invisible.
    const isFormatBuilder =
      (ctx.language === 'go' && call.name === 'Sprintf' && call.object === 'fmt') ||
      (ctx.language === 'java' && call.name === 'format' && call.object === 'String');
    if (isFormatBuilder) {
      if (!SQL_KEYWORDS.test(call.fullExpression)) return null;
      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-001',
        ruleName: 'SQL Injection',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.7,
        metadata: { method: call.name, object: call.object },
      };
    }

    // Every branch below requires actually-dynamic SQL rather than a bare
    // SQL-keyword sniff: a plain literal is a constant, including the
    // idiomatic parameterized forms (`$pdo->prepare("... WHERE id = ?")`,
    // `execute("... WHERE id = ?", (user_id,))`) whose parameters are bound
    // separately — keyword-sniffing would flag the standard safe pattern on
    // every single use.
    const hasDynamicSql = node.children.some(c => isDynamicSqlFragment(c, ctx.language));

    if (ctx.language === 'php') {
      const isBareSqlFunction = call.object === null && SQL_FUNCTIONS_PHP.includes(call.name);
      const isSqlMethodCall = call.object !== null
        && SQL_METHODS_PHP.includes(call.name)
        && SQL_OBJECTS_PHP.some(o => call.object!.toLowerCase().includes(o));
      if (!isBareSqlFunction && !isSqlMethodCall) return null;
      if (!hasDynamicSql) return null;

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-001',
        ruleName: 'SQL Injection',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.8,
        metadata: { method: call.name, object: call.object },
      };
    }

    const methods = ctx.language === 'go' ? SQL_METHODS_GO
      : ctx.language === 'java' ? SQL_METHODS_JAVA
      : SQL_METHODS;
    if (!methods.includes(call.name)) return null;

    // Check if the call target looks like a DB object
    const objects = ctx.language === 'go' ? SQL_OBJECTS_GO
      : ctx.language === 'java' ? SQL_OBJECTS_JAVA
      : SQL_OBJECTS;
    if (call.object && !objects.some(o => call.object!.toLowerCase().includes(o))) {
      return null;
    }

    if (ctx.language === 'go' || ctx.language === 'java') {
      // Only flag queries assembled dynamically — via concatenation,
      // fmt.Sprintf, or String.format. Placeholder-based queries
      // (`... WHERE id = ?`, $1) are safe.
      const usesFormatBuilder = ctx.language === 'go'
        ? /\bfmt\.Sprintf\s*\(/.test(call.fullExpression)
        : /\bString\.format\s*\(/.test(call.fullExpression);
      if (!hasDynamicSql && !usesFormatBuilder) return null;
      if (!SQL_KEYWORDS.test(call.fullExpression)) return null;
    } else {
      // Python's two string-formatting builders also count as dynamic
      // assembly when the formatted string looks like SQL — detected on the
      // literal-stripped text (`.format(` / `%` directly after a literal
      // placeholder), so wildcard text *inside* a constant (`LIKE
      // '%admin%'`, strftime's `'%Y'`) can't fake a format operator, and
      // both `% name` and the dict form `% {"id": x}` are caught.
      const usesPyFormatBuilder = ctx.language === 'python'
        && /\uFFFF\s*(?:\.\s*format\s*\(|%)/.test(stripStringLiterals(call.fullExpression))
        && SQL_KEYWORDS.test(call.fullExpression);
      if (!hasDynamicSql && !usesPyFormatBuilder) return null;

      // Exclude parameterized queries (second arg is array/object)
      if (/,\s*\[/.test(call.fullExpression)) return null;
    }

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-001',
      ruleName: 'SQL Injection',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.8,
      metadata: { method: call.name, object: call.object },
    };
  },
};

const CMD_FUNCTIONS = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'];
const CMD_OBJECTS_JS = ['child_process', 'cp', 'childProcess'];
const CMD_FUNCTIONS_PY = ['system', 'popen', 'call', 'run', 'check_output', 'check_call', 'Popen'];
const CMD_OBJECTS_PY = ['os', 'subprocess'];
const CMD_FUNCTIONS_GO = ['Command', 'CommandContext'];
// `exec` is already caught below via CMD_FUNCTIONS (isJSCmd applies to any
// non-Java language). `system`/`popen` are listed explicitly here rather
// than relying on CMD_FUNCTIONS_PY, since isPyCmd is gated to Python only —
// matching Python's generic names (`call`, `run`, `Popen`) against bare PHP
// functions would false-positive on unrelated code with those same names.
const CMD_FUNCTIONS_PHP = ['system', 'popen', 'shell_exec', 'passthru', 'proc_open'];

export const commandInjection: BuiltInRule = {
  id: 'CG-002',
  name: 'Command Injection',
  severity: 'critical',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects shell command execution with user-controlled input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const isJSCmd = ctx.language !== 'java' &&
      CMD_FUNCTIONS.includes(call.name) &&
      (!call.object || CMD_OBJECTS_JS.some(o => call.object!.includes(o)));
    const isPyCmd = ctx.language === 'python' &&
      CMD_FUNCTIONS_PY.includes(call.name) &&
      (!call.object || CMD_OBJECTS_PY.some(o => call.object!.includes(o)));
    const isGoCmd = ctx.language === 'go' &&
      CMD_FUNCTIONS_GO.includes(call.name) &&
      call.object !== null && call.object.includes('exec');
    const isJavaCmd = ctx.language === 'java' && (
      (call.name === 'exec' && call.object !== null && call.object.includes('Runtime')) ||
      call.name === 'ProcessBuilder'
    );
    const isPhpCmd = ctx.language === 'php' &&
      call.object === null &&
      CMD_FUNCTIONS_PHP.includes(call.name);

    if (!isJSCmd && !isPyCmd && !isGoCmd && !isJavaCmd && !isPhpCmd) return null;

    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || (ctx.language === 'go' && /\bfmt\.Sprintf\s*\(/.test(call.fullExpression))
      || (ctx.language === 'java' && /\bString\.format\s*\(/.test(call.fullExpression));
    if (!hasDynamic) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-002',
      ruleName: 'Command Injection',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.85,
      metadata: { method: call.name, object: call.object },
    };
  },
};

// JS/TS's native MongoDB driver and PHP's mongodb/mongodb library both use
// camelCase method names; pymongo follows Python's snake_case convention
// instead (`find_one`, not `findOne`).
const MONGO_METHODS = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace',
  'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'replaceOne', 'aggregate'];
const MONGO_UPDATE_METHODS = ['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'findOneAndReplace'];
const MONGO_METHODS_PY = ['find', 'find_one', 'find_one_and_update', 'find_one_and_delete',
  'find_one_and_replace', 'update_one', 'update_many', 'delete_one', 'delete_many',
  'replace_one', 'aggregate', 'count_documents'];
const MONGO_UPDATE_METHODS_PY = ['update_one', 'update_many', 'find_one_and_update', 'replace_one', 'find_one_and_replace'];

// `find`/`find_one` collide with unrelated, very common APIs on a non-Mongo
// receiver (Array.prototype.find, Python's str.find) — a bare method-name
// match on these two is much weaker evidence than the others, so it gets a
// reduced confidence instead of being suppressed outright (Stage 2 still
// sees it and can dismiss non-Mongo hits).
const AMBIGUOUS_METHODS = new Set(['find', 'find_one']);

// Passing the entire request object as a MongoDB filter/update document lets
// an attacker submit query operators instead of a plain value — e.g.
// `{"password": {"$ne": null}}` as the request body bypasses a password
// check entirely. A specific field access (`req.body.username`) is an
// ordinary string value and isn't the same risk, so only the *whole* object
// being passed directly (not a property of it) is flagged.
const WHOLE_REQUEST_OBJECT_JS = /^(req|request)\.(body|query|params)$/;
const WHOLE_REQUEST_OBJECT_PY = /^request\.(json|args|form|GET|POST|data)$/;
const WHOLE_REQUEST_OBJECT_PHP = /^\$_(GET|POST|REQUEST)$/;

interface NosqlConfig {
  methods: string[];
  updateMethods: string[];
  wholeObjectPattern: RegExp;
}

// Each language's Mongo-driver method names + whole-object pattern, keyed by
// language so the two stay paired instead of drifting apart as independent
// ternary chains.
const NOSQL_CONFIG: Partial<Record<Language, NosqlConfig>> = {
  python: {
    methods: MONGO_METHODS_PY,
    updateMethods: MONGO_UPDATE_METHODS_PY,
    wholeObjectPattern: WHOLE_REQUEST_OBJECT_PY,
  },
  php: {
    methods: MONGO_METHODS,
    updateMethods: MONGO_UPDATE_METHODS,
    wholeObjectPattern: WHOLE_REQUEST_OBJECT_PHP,
  },
};
const DEFAULT_NOSQL_CONFIG: NosqlConfig = {
  methods: MONGO_METHODS,
  updateMethods: MONGO_UPDATE_METHODS,
  wholeObjectPattern: WHOLE_REQUEST_OBJECT_JS,
};

// `$where` executes its string as arbitrary JavaScript inside MongoDB
// itself — string-building its content is effectively server-side code
// injection, the NoSQL analogue of CG-003.
const WHERE_CLAUSE = '$where';

// Finds where the `$where` key's *value* begins, so a dynamic fragment can be
// checked for actually being that value rather than merely appearing
// somewhere later in the same call (e.g. an unrelated sibling field like
// `find({$where: "x"}, {note: \`${n}\`})`, where the template belongs to `note`).
// Skips an optional quote closing the key itself, then whitespace, then the
// key/value separator (`:` for JS/Python/PHP object literals, `=>` for PHP arrays).
function findWhereValueStart(fullExpression: string, whereIndex: number): number {
  let i = whereIndex + WHERE_CLAUSE.length;
  if (fullExpression[i] === '\'' || fullExpression[i] === '"') i += 1;
  while (i < fullExpression.length && /\s/.test(fullExpression[i])) i += 1;
  if (fullExpression.slice(i, i + 2) === '=>') i += 2;
  else if (fullExpression[i] === ':') i += 1;
  while (i < fullExpression.length && /\s/.test(fullExpression[i])) i += 1;
  return i;
}

export const nosqlInjection: BuiltInRule = {
  id: 'CG-024',
  name: 'NoSQL Injection',
  severity: 'high',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'php'],
  description: 'Detects MongoDB queries built from an entire user-controlled request object, a raw update document, or a dynamically-built $where clause, allowing query-operator or code injection.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;
    if (call.object === null) return null;

    const config = NOSQL_CONFIG[ctx.language] ?? DEFAULT_NOSQL_CONFIG;
    if (!config.methods.includes(call.name)) return null;

    const whereIndex = call.fullExpression.indexOf(WHERE_CLAUSE);
    const whereValueStart = whereIndex !== -1 ? findWhereValueStart(call.fullExpression, whereIndex) : -1;
    const hasWhereInjection = whereIndex !== -1 && node.children.some(c => {
      if (c.type !== 'template_string' && c.type !== 'string_concat') return false;
      return call.fullExpression.indexOf(c.text, whereValueStart) === whereValueStart;
    });

    // Filter (arg 0) is dangerous for every method; the update/replacement
    // document (arg 1) is equally dangerous for the update-family methods —
    // `updateOne({_id}, req.body)` lets an attacker inject $set/$rename.
    const argsText = getArgumentsText(call.fullExpression);
    const args = argsText !== null ? splitTopLevelArgs(argsText) : [];
    const dangerousArgIndexes = config.updateMethods.includes(call.name) ? [0, 1] : [0];
    const isWholeObjectPass = dangerousArgIndexes.some(
      i => args[i] !== undefined && config.wholeObjectPattern.test(args[i])
    );

    if (!hasWhereInjection && !isWholeObjectPass) return null;

    const isAmbiguous = AMBIGUOUS_METHODS.has(call.name) && !hasWhereInjection;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-024',
      ruleName: 'NoSQL Injection',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: isAmbiguous ? 0.5 : 0.7,
      metadata: { method: call.name, object: call.object },
    };
  },
};

const EVAL_FUNCTIONS = ['eval', 'Function', 'setTimeout', 'setInterval'];
// The timer functions are only eval-like in their legacy string form:
// `setTimeout("doThing()", 100)`. The overwhelmingly common function form
// (`setTimeout(() => ..., ms)`, `setTimeout(resolve, ms)`) executes nothing
// from a string, and receiver variants (`server.setTimeout(ms)`,
// `session.setTimeout(...)`) are socket-timeout APIs with no code argument.
const TIMER_FUNCTIONS = new Set(['setTimeout', 'setInterval']);

// Global-object aliases through which the eval-like timer is still the
// timer: `window.setTimeout("code", ms)` evaluates its string exactly like
// the bare call. Any other receiver (`server.setTimeout(ms)`,
// `session.setTimeout(...)`) is a socket-timeout API with no code argument.
const GLOBAL_RECEIVERS = new Set(['window', 'globalThis', 'self', 'global']);

function timerFirstArgIsStringCode(fullExpression: string): boolean {
  const argsText = getArgumentsText(fullExpression);
  if (argsText === null) return false;
  const first = (splitTopLevelArgs(argsText)[0] ?? '').trim();
  // The argument itself must be a string expression. A leading quote is
  // definitive. Otherwise reject function-shaped arguments outright —
  // callbacks routinely *contain* quotes and `+` in their bodies
  // (`() => log('retry ' + n)`) without evaluating any string — and only
  // then accept a concatenation involving a literal (`"do" + action`).
  if (/^['"`]/.test(first)) return true;
  if (/^(?:async\b|function\b|\()/.test(first) || first.includes('=>')) return false;
  return first.includes('+') && /['"`]/.test(first);
}

export const codeInjection: BuiltInRule = {
  id: 'CG-003',
  name: 'Code Injection (eval)',
  severity: 'critical',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'php'],
  description: 'Detects use of eval() or equivalent functions with dynamic input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    // Python's built-in `exec(...)` runs arbitrary code just like `eval` —
    // gated to Python and to the bare builtin (no receiver), since `exec` on
    // a receiver, and `exec`/`shell_exec` in JS/PHP, are command execution
    // (CG-002's job), not code injection.
    const isPythonExec = ctx.language === 'python' && call.name === 'exec' && call.object === null;
    if (!EVAL_FUNCTIONS.includes(call.name) && !isPythonExec) return null;

    if (TIMER_FUNCTIONS.has(call.name)) {
      if (call.object !== null && !GLOBAL_RECEIVERS.has(call.object)) return null;
      if (!timerFirstArgIsStringCode(call.fullExpression)) return null;
    }

    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || call.fullExpression.includes('${');

    // eval with literal strings is less dangerous but still worth flagging
    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-003',
      ruleName: 'Code Injection (eval)',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: hasDynamic ? 0.9 : 0.6,
      metadata: { method: call.name, dynamic: hasDynamic },
    };
  },
};
