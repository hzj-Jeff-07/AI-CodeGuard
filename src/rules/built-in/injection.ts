import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const SQL_METHODS = ['query', 'execute', 'raw', 'exec', 'prepare'];
const SQL_METHODS_GO = ['Query', 'QueryRow', 'QueryContext', 'QueryRowContext', 'Exec', 'ExecContext', 'Prepare', 'PrepareContext'];
const SQL_OBJECTS = ['db', 'database', 'connection', 'conn', 'pool', 'client', 'knex', 'sequelize', 'prisma'];
const SQL_OBJECTS_GO = ['db', 'database', 'conn', 'pool', 'tx', 'stmt'];
const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|WHERE|FROM|JOIN)\b/i;

export const sqlInjection: BuiltInRule = {
  id: 'CG-001',
  name: 'SQL Injection',
  severity: 'critical',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'go'],
  description: 'Detects unparameterized SQL queries built with string concatenation, template literals, or fmt.Sprintf.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    // Go: fmt.Sprintf assembling a SQL string is suspicious on its own —
    // Stage 1 has no dataflow, so the later db.Query(variable) is invisible.
    if (ctx.language === 'go' && call.name === 'Sprintf' && call.object === 'fmt') {
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

    const methods = ctx.language === 'go' ? SQL_METHODS_GO : SQL_METHODS;
    if (!methods.includes(call.name)) return null;

    // Check if the call target looks like a DB object
    const objects = ctx.language === 'go' ? SQL_OBJECTS_GO : SQL_OBJECTS;
    if (call.object && !objects.some(o => call.object!.toLowerCase().includes(o))) {
      return null;
    }

    const hasConcatOrTemplate = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    );

    if (ctx.language === 'go') {
      // Go: only flag queries assembled dynamically — via concatenation or
      // fmt.Sprintf. Placeholder-based queries (`... WHERE id = ?`, $1) are safe.
      const usesSprintf = /\bfmt\.Sprintf\s*\(/.test(call.fullExpression);
      if (!hasConcatOrTemplate && !usesSprintf) return null;
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

export const commandInjection: BuiltInRule = {
  id: 'CG-002',
  name: 'Command Injection',
  severity: 'critical',
  category: 'injection',
  languages: ['javascript', 'typescript', 'python', 'go'],
  description: 'Detects shell command execution with user-controlled input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const isJSCmd = CMD_FUNCTIONS.includes(call.name) &&
      (!call.object || CMD_OBJECTS_JS.some(o => call.object!.includes(o)));
    const isPyCmd = CMD_FUNCTIONS_PY.includes(call.name) &&
      (!call.object || CMD_OBJECTS_PY.some(o => call.object!.includes(o)));
    const isGoCmd = ctx.language === 'go' &&
      CMD_FUNCTIONS_GO.includes(call.name) &&
      call.object !== null && call.object.includes('exec');

    if (!isJSCmd && !isPyCmd && !isGoCmd) return null;

    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || (ctx.language === 'go' && /\bfmt\.Sprintf\s*\(/.test(call.fullExpression));
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
  languages: ['javascript', 'typescript', 'python'],
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
