import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import { findOuterArgumentsStart } from '../../parser/languages/shared.js';

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

    if (ctx.language === 'php') {
      const isBareSqlFunction = call.object === null && SQL_FUNCTIONS_PHP.includes(call.name);
      const isSqlMethodCall = call.object !== null
        && SQL_METHODS_PHP.includes(call.name)
        && SQL_OBJECTS_PHP.some(o => call.object!.toLowerCase().includes(o));
      if (!isBareSqlFunction && !isSqlMethodCall) return null;

      // Unlike the other languages, require actual concatenation/interpolation
      // here rather than falling back to a bare SQL-keyword sniff: PDO's
      // idiomatic `$pdo->prepare("SELECT ... WHERE id = ?")` takes the SQL
      // string as its only argument (parameters are bound separately via a
      // later `execute([...])` call), so keyword-sniffing a plain literal
      // would flag the standard safe pattern on every single use.
      const hasConcatOrTemplate = node.children.some(
        c => c.type === 'template_string' || c.type === 'string_concat'
      );
      if (!hasConcatOrTemplate) return null;

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

    const hasConcatOrTemplate = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    );

    if (ctx.language === 'go' || ctx.language === 'java') {
      // Only flag queries assembled dynamically — via concatenation,
      // fmt.Sprintf, or String.format. Placeholder-based queries
      // (`... WHERE id = ?`, $1) are safe.
      const usesFormatBuilder = ctx.language === 'go'
        ? /\bfmt\.Sprintf\s*\(/.test(call.fullExpression)
        : /\bString\.format\s*\(/.test(call.fullExpression);
      if (!hasConcatOrTemplate && !usesFormatBuilder) return null;
      if (!SQL_KEYWORDS.test(call.fullExpression)) return null;
    } else {
      if (!hasConcatOrTemplate && !SQL_KEYWORDS.test(call.fullExpression)) return null;

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
// instead (`find_one`, not `findOne`) — only `find`/`aggregate` are spelled
// the same in both.
const MONGO_METHODS = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace',
  'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'replaceOne', 'aggregate'];
const MONGO_METHODS_PY = ['find', 'find_one', 'find_one_and_update', 'find_one_and_delete',
  'find_one_and_replace', 'update_one', 'update_many', 'delete_one', 'delete_many',
  'replace_one', 'aggregate', 'count_documents'];

// Passing the entire request object as a MongoDB filter/update document lets
// an attacker submit query operators instead of a plain value — e.g.
// `{"password": {"$ne": null}}` as the request body bypasses a password
// check entirely. A specific field access (`req.body.username`) is an
// ordinary string value and isn't the same risk, so only the *whole* object
// being passed directly (not a property of it) is flagged.
const WHOLE_REQUEST_OBJECT_JS = /^(req|request)\.(body|query|params)$/;
const WHOLE_REQUEST_OBJECT_PY = /^request\.(json|args|form|GET|POST|data)$/;
const WHOLE_REQUEST_OBJECT_PHP = /^\$_(GET|POST|REQUEST)$/;

// `$where` executes its string as arbitrary JavaScript inside MongoDB
// itself — string-building its content is effectively server-side code
// injection, the NoSQL analogue of CG-003.
const WHERE_CLAUSE = /\$where/;

function firstArgText(fullExpression: string): string | null {
  const argsStart = findOuterArgumentsStart(fullExpression);
  if (argsStart === -1) return null;
  const argsText = fullExpression.slice(argsStart + 1, fullExpression.lastIndexOf(')')).trim();
  return argsText.split(',')[0].trim();
}

export const nosqlInjection: BuiltInRule = {
  id: 'CG-024',
  name: 'NoSQL Injection',
  severity: 'high',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'php'],
  description: 'Detects MongoDB queries built from an entire user-controlled request object or a dynamically-built $where clause, allowing query-operator or code injection.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const mongoMethods = ctx.language === 'python' ? MONGO_METHODS_PY : MONGO_METHODS;
    if (call.object === null || !mongoMethods.includes(call.name)) return null;

    const hasWhereInjection = WHERE_CLAUSE.test(call.fullExpression) && node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    );

    const firstArg = firstArgText(call.fullExpression);
    const wholeObjectPattern = ctx.language === 'python' ? WHOLE_REQUEST_OBJECT_PY
      : ctx.language === 'php' ? WHOLE_REQUEST_OBJECT_PHP
      : WHOLE_REQUEST_OBJECT_JS;
    const isWholeObjectPass = firstArg !== null && wholeObjectPattern.test(firstArg);

    if (!hasWhereInjection && !isWholeObjectPass) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-024',
      ruleName: 'NoSQL Injection',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.7,
      metadata: { method: call.name, object: call.object },
    };
  },
};

const EVAL_FUNCTIONS = ['eval', 'Function', 'setTimeout', 'setInterval'];

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

    if (!EVAL_FUNCTIONS.includes(call.name)) return null;

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
