import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const SENSITIVE_PATTERNS = /\b(ssn|social.?security|credit.?card|card.?number|cvv|expir|bank.?account)\b/i;
const LOG_FUNCTIONS = ['log', 'info', 'warn', 'error', 'debug', 'trace', 'console.log', 'print', 'logging'];
const LOG_OBJECTS_GO = ['log', 'logger', 'logrus', 'zap', 'zerolog'];
const LOG_METHODS_GO = ['println', 'printf', 'print', 'info', 'infof', 'error', 'errorf',
  'warn', 'warnf', 'debug', 'debugf', 'fatal', 'fatalf'];
const LOG_OBJECTS_JAVA = ['logger', 'log', 'system.out', 'system.err'];
const LOG_METHODS_JAVA = ['println', 'print', 'info', 'debug', 'warn', 'error', 'trace', 'fatal'];

export const sensitiveDataExposure: BuiltInRule = {
  id: 'CG-040',
  name: 'Sensitive Data Exposure',
  severity: 'medium',
  category: 'data',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  description: 'Detects logging or exposure of sensitive data such as passwords, tokens, or PII.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    let isLogCall: boolean;
    if (ctx.language === 'go') {
      isLogCall = call.object !== null
        && LOG_OBJECTS_GO.some(o => call.object!.toLowerCase().includes(o))
        && LOG_METHODS_GO.includes(call.name.toLowerCase());
    } else if (ctx.language === 'java') {
      isLogCall = call.object !== null
        && LOG_OBJECTS_JAVA.some(o => call.object!.toLowerCase().includes(o))
        && LOG_METHODS_JAVA.includes(call.name.toLowerCase());
    } else {
      // Bare call names stay case-sensitive: lowercasing would make `new
      // Error(...)` collide with the `error` entry in LOG_FUNCTIONS. Only
      // the receiver object is matched case-insensitively, mirroring the
      // Go/Java branches above (`Logger.fatal(...)` should match `logger`).
      isLogCall = LOG_FUNCTIONS.includes(call.name) ||
        (call.object !== null && ['console', 'logger', 'log', 'logging'].includes(call.object.toLowerCase()));
    }
    if (!isLogCall) return null;

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
  languages: ['javascript', 'typescript', 'python', 'java'],
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

    // JS: node-serialize, serialize-javascript
    if (DESER_FUNCTIONS_JS.includes(call.name)) {
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
