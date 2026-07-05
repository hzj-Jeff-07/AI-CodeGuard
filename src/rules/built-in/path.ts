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
// PHP's file functions are global (no receiver), like Python's.
const PATH_FUNCTIONS_PHP = ['file_get_contents', 'file_put_contents', 'fopen', 'readfile',
  'unlink', 'copy', 'rename', 'mkdir', 'rmdir', 'is_file', 'file_exists'];

export const pathTraversal: BuiltInRule = {
  id: 'CG-030',
  name: 'Path Traversal',
  severity: 'high',
  category: 'path',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
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
    } else if (ctx.language === 'php') {
      if (call.object !== null || !PATH_FUNCTIONS_PHP.includes(call.name)) return null;
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

const READ_WRITE_FN = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'open'];
const USER_INPUT_JS_PY = /\b(req\.|params\.|query\.|body\.|request\.|args\.|argv)/;

const READ_WRITE_GO = ['Open', 'OpenFile', 'Create', 'ReadFile', 'WriteFile'];
const READ_WRITE_OBJECTS_GO = ['os', 'ioutil'];
// net/http's Request fields and common router libs (gorilla/mux, gin) are the
// usual sources of attacker-controlled path segments in Go web handlers.
const USER_INPUT_GO = /\b(r\.URL\.Query|r\.FormValue|r\.PostFormValue|mux\.Vars|c\.Param\(|c\.Query\(|os\.Args)\b/;

const READ_WRITE_CONSTRUCTORS_JAVA = ['File', 'FileInputStream', 'FileOutputStream',
  'FileReader', 'FileWriter'];
const READ_WRITE_METHODS_JAVA = ['readAllBytes', 'write', 'newInputStream', 'newOutputStream'];
const READ_WRITE_OBJECTS_JAVA = ['Files', 'Paths', 'Path'];
const USER_INPUT_JAVA = /\b(getParameter|getHeader|getQueryString)\b/;

const READ_WRITE_PHP = ['file_get_contents', 'file_put_contents', 'fopen', 'readfile'];
const USER_INPUT_PHP = /\$_(GET|POST|REQUEST|COOKIE)\b/;

export const arbitraryFileAccess: BuiltInRule = {
  id: 'CG-031',
  name: 'Arbitrary File Read/Write',
  severity: 'high',
  category: 'path',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php'],
  description: 'Detects file read/write operations where the path comes from external input.',

  check(node: ASTNode, ctx: RuleCheckContext): SuspiciousNode | null {
    if (node.type !== 'function_call') return null;

    const call = ctx.extractCallInfo(node);
    if (!call) return null;

    let matchesTarget: boolean;
    if (ctx.language === 'go') {
      matchesTarget = READ_WRITE_GO.includes(call.name)
        && call.object !== null && READ_WRITE_OBJECTS_GO.includes(call.object);
    } else if (ctx.language === 'java') {
      const isConstructor = !call.object && READ_WRITE_CONSTRUCTORS_JAVA.includes(call.name);
      const isStaticHelper = call.object !== null
        && READ_WRITE_OBJECTS_JAVA.includes(call.object)
        && READ_WRITE_METHODS_JAVA.includes(call.name);
      matchesTarget = isConstructor || isStaticHelper;
    } else if (ctx.language === 'php') {
      matchesTarget = call.object === null && READ_WRITE_PHP.includes(call.name);
    } else {
      matchesTarget = READ_WRITE_FN.includes(call.name);
    }
    if (!matchesTarget) return null;

    // Check if the path argument references a source of external input
    const text = call.fullExpression;
    let hasUserInput: boolean;
    if (ctx.language === 'go') {
      hasUserInput = USER_INPUT_GO.test(text);
    } else if (ctx.language === 'java') {
      hasUserInput = USER_INPUT_JAVA.test(text);
    } else if (ctx.language === 'php') {
      hasUserInput = USER_INPUT_PHP.test(text);
    } else {
      hasUserInput = USER_INPUT_JS_PY.test(text);
    }
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
