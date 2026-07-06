import type { ASTNode, CallInfo, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const SENSITIVE_PATTERNS = /\b(ssn|social.?security|credit.?card|card.?number|cvv|expir|bank.?account)\b/i;
const LOG_FUNCTIONS = ['log', 'info', 'warn', 'error', 'debug', 'trace', 'console.log', 'print', 'logging'];
const LOG_OBJECTS_GO = ['log', 'logger', 'logrus', 'zap', 'zerolog'];
const LOG_METHODS_GO = ['println', 'printf', 'print', 'info', 'infof', 'error', 'errorf',
  'warn', 'warnf', 'debug', 'debugf', 'fatal', 'fatalf'];
const LOG_OBJECTS_JAVA = ['logger', 'log', 'system.out', 'system.err'];
const LOG_METHODS_JAVA = ['println', 'print', 'info', 'debug', 'warn', 'error', 'trace', 'fatal'];
const LOG_OBJECTS_PHP = ['log', 'logger'];
const LOG_METHODS_PHP = ['info', 'debug', 'warn', 'warning', 'error', 'critical',
  'emergency', 'alert', 'notice', 'log'];
// error_log/syslog are PHP's bare global logging functions (no receiver).
const LOG_FUNCTIONS_PHP = ['error_log', 'syslog'];

// Each language's log-call matcher, keyed by language so adding a new one is
// a single map entry instead of another branch in an if/else chain.
// `javascript`/`typescript`/`python` share the default (no entry needed).
const LOG_CALL_MATCHERS: Partial<Record<Language, (call: CallInfo) => boolean>> = {
  go: call => call.object !== null
    && LOG_OBJECTS_GO.some(o => call.object!.toLowerCase().includes(o))
    && LOG_METHODS_GO.includes(call.name.toLowerCase()),
  java: call => call.object !== null
    && LOG_OBJECTS_JAVA.some(o => call.object!.toLowerCase().includes(o))
    && LOG_METHODS_JAVA.includes(call.name.toLowerCase()),
  // PHP function calls are case-insensitive at the language level (unlike
  // JS, where `new Error(...)` must stay case-sensitive to avoid colliding
  // with the `error` entry in LOG_FUNCTIONS), so lowercasing the bare
  // function name here is safe.
  php: call => LOG_FUNCTIONS_PHP.includes(call.name.toLowerCase()) ||
    (call.object !== null
      && LOG_OBJECTS_PHP.some(o => call.object!.toLowerCase().includes(o))
      && LOG_METHODS_PHP.includes(call.name.toLowerCase())),
};
// Bare call names stay case-sensitive: lowercasing would make `new
// Error(...)` collide with the `error` entry in LOG_FUNCTIONS. Only the
// receiver object is matched case-insensitively, mirroring the Go/Java
// matchers above (`Logger.fatal(...)` should match `logger`).
const DEFAULT_LOG_CALL_MATCHER = (call: CallInfo): boolean =>
  LOG_FUNCTIONS.includes(call.name) ||
  (call.object !== null && ['console', 'logger', 'log', 'logging'].includes(call.object.toLowerCase()));

export const sensitiveDataExposure: BuiltInRule = {
  id: 'CG-040',
  name: 'Sensitive Data Exposure',
  severity: 'medium',
  category: 'data',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects logging or exposure of sensitive data such as passwords, tokens, or PII.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const matcher = LOG_CALL_MATCHERS[ctx.language] ?? DEFAULT_LOG_CALL_MATCHER;
    if (!matcher(call)) return null;

    const text = call.fullExpression.toLowerCase();
    if (SENSITIVE_PATTERNS.test(text) ||
      /\b(password|token|secret|api.?key|credentials?)\b/i.test(text)) {
      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-040',
        ruleName: 'Sensitive Data Exposure',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 2),
        confidence: 0.65,
        metadata: { method: call.name },
      };
    }

    return null;
  },
};

const DESER_FUNCTIONS_JS = ['deserialize', 'unserialize'];
const DESER_FUNCTIONS_PY = ['loads', 'load'];
const DESER_MODULES_PY = ['pickle', 'yaml', 'marshal'];

export const insecureDeserialization: BuiltInRule = {
  id: 'CG-041',
  name: 'Insecure Deserialization',
  severity: 'high',
  category: 'data',
  languages: ['javascript', 'typescript', 'python', 'java', 'php'],
  description: 'Detects deserialization of untrusted data (pickle, yaml.load, ObjectInputStream, etc.).',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    // Java: ObjectInputStream#readObject / XMLDecoder#readObject are the
    // classic gadget-chain vector; the method name alone is an unambiguous
    // signal (no unrelated Java API shares it), so no receiver check needed.
    if (ctx.language === 'java' && call.name === 'readObject') {
      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-041',
        ruleName: 'Insecure Deserialization',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.8,
        metadata: { method: call.name },
      };
    }

    // JS: node-serialize, serialize-javascript. Also covers PHP's bare
    // global `unserialize()` — the classic PHP object-injection gadget-chain
    // vector — since both languages' rule branch reach this same check.
    if (DESER_FUNCTIONS_JS.includes(call.name)) {
      // PHP's dangerous global `unserialize()` takes no receiver. A method
      // named `unserialize` on an object (e.g. implementing the standard
      // `Serializable` interface) is an unrelated, benign pattern that just
      // happens to share the name — only the bare call is the gadget-chain
      // vector.
      if (ctx.language === 'php' && call.object !== null) {
        return null;
      }

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-041',
        ruleName: 'Insecure Deserialization',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.8,
        metadata: { method: call.name },
      };
    }

    // Python: pickle.loads, yaml.load (without SafeLoader)
    if (ctx.language === 'python' && DESER_FUNCTIONS_PY.includes(call.name) &&
      call.object && DESER_MODULES_PY.includes(call.object)) {
      // yaml.safe_load is fine, yaml.load without Loader is not
      if (call.object === 'yaml' && call.name === 'load') {
        if (call.fullExpression.includes('SafeLoader') || call.fullExpression.includes('safe_load')) {
          return null;
        }
      }

      return {
        file: ctx.file,
        language: ctx.language,
        ruleId: 'CG-041',
        ruleName: 'Insecure Deserialization',
        node,
        location: node.location,
        snippet: ctx.getSnippet(node),
        context: ctx.getContext(node, 3),
        confidence: 0.85,
        metadata: { method: call.name, module: call.object },
      };
    }

    return null;
  },
};
