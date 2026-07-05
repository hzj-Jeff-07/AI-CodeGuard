import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

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
// `exec`/`system`/`popen` are already caught below via CMD_FUNCTIONS /
// CMD_FUNCTIONS_PY (PHP shares those names); these three have no equivalent
// in the other languages' lists.
const CMD_FUNCTIONS_PHP = ['shell_exec', 'passthru', 'proc_open'];

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
    const isPyCmd = CMD_FUNCTIONS_PY.includes(call.name) &&
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
