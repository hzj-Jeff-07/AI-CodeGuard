import type { ASTNode, CallInfo, Language, SuspiciousNode } from '../../types/index.js';
import type { BuiltInRule, RuleCheckContext } from '../engine.js';
import {
  getArgumentsText,
  USER_INPUT_GO,
  USER_INPUT_JAVA,
  USER_INPUT_JS_PY,
  USER_INPUT_PHP,
} from '../../parser/languages/shared.js';

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

// Each language's file-operation matcher, keyed by language so adding a new
// one is a single map entry instead of another branch in an if/else chain.
// `javascript`/`typescript` share the default (no entry needed).
const PATH_OP_MATCHERS: Partial<Record<Language, (call: CallInfo) => boolean>> = {
  go: call => PATH_FUNCTIONS_GO.includes(call.name)
    && call.object !== null && PATH_OBJECTS_GO.includes(call.object),
  java: call => {
    const isConstructor = !call.object && PATH_CONSTRUCTORS_JAVA.includes(call.name);
    const isStaticHelper = call.object !== null
      && PATH_OBJECTS_JAVA.includes(call.object)
      && PATH_METHODS_JAVA.includes(call.name);
    return isConstructor || isStaticHelper;
  },
  php: call => call.object === null && PATH_FUNCTIONS_PHP.includes(call.name),
  python: call => PATH_FUNCTIONS_PY.includes(call.name),
};
const DEFAULT_PATH_OP_MATCHER = (call: CallInfo): boolean => PATH_FUNCTIONS_JS.includes(call.name);

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

    const matcher = PATH_OP_MATCHERS[ctx.language] ?? DEFAULT_PATH_OP_MATCHER;
    if (!matcher(call)) return null;

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

// The path is passed by variable, not inline (`path := r.URL.Query...; os.Open(path)`),
// so the direct-text check below never sees the user-input pattern. If the
// argument is a bare identifier, check whether it was itself assigned from a
// user-input source nearby.
function firstArgIdentifier(fullExpression: string): string | null {
  const argsText = getArgumentsText(fullExpression);
  if (argsText === null) return null;
  const firstArg = argsText.split(',')[0].trim();
  return /^\$?[A-Za-z_][A-Za-z0-9_]*$/.test(firstArg) ? firstArg : null;
}

interface FileAccessConfig {
  matchesTarget: (call: CallInfo) => boolean;
  userInputPattern: RegExp;
}

const READ_WRITE_FN = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'open'];

const READ_WRITE_GO = ['Open', 'OpenFile', 'Create', 'ReadFile', 'WriteFile'];
const READ_WRITE_OBJECTS_GO = ['os', 'ioutil'];

const READ_WRITE_CONSTRUCTORS_JAVA = ['File', 'FileInputStream', 'FileOutputStream',
  'FileReader', 'FileWriter'];
const READ_WRITE_METHODS_JAVA = ['readAllBytes', 'write', 'newInputStream', 'newOutputStream'];
const READ_WRITE_OBJECTS_JAVA = ['Files', 'Paths', 'Path'];

const READ_WRITE_PHP = ['file_get_contents', 'file_put_contents', 'fopen', 'readfile'];

const FILE_ACCESS_CONFIG: Partial<Record<Language, FileAccessConfig>> = {
  go: {
    matchesTarget: call => READ_WRITE_GO.includes(call.name)
      && call.object !== null && READ_WRITE_OBJECTS_GO.includes(call.object),
    userInputPattern: USER_INPUT_GO,
  },
  java: {
    matchesTarget: call => {
      const isConstructor = !call.object && READ_WRITE_CONSTRUCTORS_JAVA.includes(call.name);
      const isStaticHelper = call.object !== null
        && READ_WRITE_OBJECTS_JAVA.includes(call.object)
        && READ_WRITE_METHODS_JAVA.includes(call.name);
      return isConstructor || isStaticHelper;
    },
    userInputPattern: USER_INPUT_JAVA,
  },
  php: {
    matchesTarget: call => call.object === null && READ_WRITE_PHP.includes(call.name),
    userInputPattern: USER_INPUT_PHP,
  },
};
const DEFAULT_FILE_ACCESS_CONFIG: FileAccessConfig = {
  matchesTarget: call => READ_WRITE_FN.includes(call.name),
  userInputPattern: USER_INPUT_JS_PY,
};

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

    const config = FILE_ACCESS_CONFIG[ctx.language] ?? DEFAULT_FILE_ACCESS_CONFIG;
    if (!config.matchesTarget(call)) return null;

    // Check if the path argument references a source of external input,
    // either inline or (for a bare identifier argument) via a nearby assignment.
    const text = call.fullExpression;
    let hasUserInput = config.userInputPattern.test(text);
    if (!hasUserInput) {
      const argName = firstArgIdentifier(text);
      hasUserInput = argName !== null && ctx.wasAssignedFrom(argName, config.userInputPattern, node);
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
