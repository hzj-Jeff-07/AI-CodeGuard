import type { ASTNode, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';

const PATH_FUNCTIONS_JS = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync',
  'createReadStream', 'createWriteStream', 'access', 'accessSync', 'open', 'openSync',
  'unlink', 'unlinkSync', 'readdir', 'readdirSync', 'stat', 'statSync'];
const PATH_FUNCTIONS_PY = ['open', 'read', 'write', 'listdir', 'remove', 'unlink',
  'makedirs', 'rmdir'];
const PATH_FUNCTIONS_GO = ['Open', 'OpenFile', 'Create', 'ReadFile', 'WriteFile',
  'Remove', 'RemoveAll', 'ReadDir', 'Mkdir', 'MkdirAll'];
const PATH_OBJECTS_GO = ['os', 'ioutil'];
// Constructors (`new File(...)`) have no receiver; static helpers are gated on
// the Files/Paths receiver so e.g. `map.get(...)` never matches.
const PATH_CONSTRUCTORS_JAVA = ['File', 'FileInputStream', 'FileOutputStream',
  'FileReader', 'FileWriter', 'RandomAccessFile'];
const PATH_METHODS_JAVA = ['readAllBytes', 'readAllLines', 'readString', 'write',
  'writeString', 'newInputStream', 'newOutputStream', 'newBufferedReader',
  'newBufferedWriter', 'delete', 'deleteIfExists', 'createDirectories', 'get', 'of'];
const PATH_OBJECTS_JAVA = ['Files', 'Paths', 'Path'];

export const pathTraversal: BuiltInRule = {
  id: 'CG-030',
  name: 'Path Traversal',
  severity: 'high',
  category: 'path',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  description: 'Detects file operations with user-controlled paths that may allow directory traversal.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    if (ctx.language === 'go') {
      if (!PATH_FUNCTIONS_GO.includes(call.name)) return null;
      if (!call.object || !PATH_OBJECTS_GO.includes(call.object)) return null;
    } else if (ctx.language === 'java') {
      const isConstructor = !call.object && PATH_CONSTRUCTORS_JAVA.includes(call.name);
      const isStaticHelper = call.object !== null
        && PATH_OBJECTS_JAVA.includes(call.object)
        && PATH_METHODS_JAVA.includes(call.name);
      if (!isConstructor && !isStaticHelper) return null;
    } else {
      const fns = ctx.language === 'python' ? PATH_FUNCTIONS_PY : PATH_FUNCTIONS_JS;
      if (!fns.includes(call.name)) return null;
    }

    const hasDynamic = node.children.some(
      c => c.type === 'template_string' || c.type === 'string_concat'
    ) || (ctx.language === 'go' && /\bfmt\.Sprintf\s*\(/.test(call.fullExpression))
      || (ctx.language === 'java' && /\bString\.format\s*\(/.test(call.fullExpression));
    if (!hasDynamic) return null;

    // Check for path sanitization in context
    const context = ctx.getContext(node, 3);
    if (context.includes('path.resolve') && context.includes('startsWith')) {
      return null; // Likely sanitized
    }
    if (ctx.language === 'go' && context.includes('filepath.Clean') && context.includes('HasPrefix')) {
      return null; // Likely sanitized
    }
    if (ctx.language === 'java'
      && (context.includes('normalize') || context.includes('getCanonicalPath'))
      && context.includes('startsWith')) {
      return null; // Likely sanitized
    }

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-030',
      ruleName: 'Path Traversal',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.75,
      metadata: { method: call.name },
    };
  },
};

export const arbitraryFileAccess: BuiltInRule = {
  id: 'CG-031',
  name: 'Arbitrary File Read/Write',
  severity: 'high',
  category: 'path',
  languages: ['javascript', 'typescript', 'python'],
  description: 'Detects file read/write operations where the path comes from external input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    const readWrite = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'open'];
    if (!readWrite.includes(call.name)) return null;

    // Check if path argument references req, params, query, body
    const text = call.fullExpression;
    const hasUserInput = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv)/.test(text);
    if (!hasUserInput) return null;

    return {
      file: ctx.file,
      language: ctx.language,
      ruleId: 'CG-031',
      ruleName: 'Arbitrary File Read/Write',
      node,
      location: node.location,
      snippet: ctx.getSnippet(node),
      context: ctx.getContext(node, 3),
      confidence: 0.8,
      metadata: { method: call.name },
    };
  },
};
