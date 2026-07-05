import { describe, it, expect } from 'vitest';
import { parse, detectLanguage, getAdapter, getSupportedExtensions } from '../../src/parser/index.js';
import { walkAST } from '../../src/parser/ast-walker.js';
import { javascriptAdapter, typescriptAdapter } from '../../src/parser/languages/javascript.js';
import { pythonAdapter } from '../../src/parser/languages/python.js';

// ── detectLanguage ──────────────────────────────────────────────

describe('detectLanguage', () => {
  it('maps .js to javascript', () => {
    expect(detectLanguage('app.js')).toBe('javascript');
  });

  it('maps .jsx to javascript', () => {
    expect(detectLanguage('App.jsx')).toBe('javascript');
  });

  it('maps .mjs to javascript', () => {
    expect(detectLanguage('index.mjs')).toBe('javascript');
  });

  it('maps .cjs to javascript', () => {
    expect(detectLanguage('config.cjs')).toBe('javascript');
  });

  it('maps .ts to typescript', () => {
    expect(detectLanguage('index.ts')).toBe('typescript');
  });

  it('maps .tsx to typescript', () => {
    expect(detectLanguage('App.tsx')).toBe('typescript');
  });

  it('maps .py to python', () => {
    expect(detectLanguage('main.py')).toBe('python');
  });

  it('maps .go to go', () => {
    expect(detectLanguage('main.go')).toBe('go');
  });

  it('maps .java to java', () => {
    expect(detectLanguage('Main.java')).toBe('java');
  });

  it('maps .php to php', () => {
    expect(detectLanguage('index.php')).toBe('php');
  });

  it('returns null for unsupported extensions', () => {
    expect(detectLanguage('style.css')).toBeNull();
    expect(detectLanguage('README.md')).toBeNull();
    expect(detectLanguage('Makefile')).toBeNull();
  });

  it('handles paths with directories', () => {
    expect(detectLanguage('src/utils/helper.ts')).toBe('typescript');
  });
});

// ── getAdapter ───────────────────────────────────────────────────

describe('getAdapter', () => {
  it('returns javascript adapter', () => {
    const adapter = getAdapter('javascript');
    expect(adapter.language).toBe('javascript');
  });

  it('returns typescript adapter', () => {
    const adapter = getAdapter('typescript');
    expect(adapter.language).toBe('typescript');
  });

  it('returns python adapter', () => {
    const adapter = getAdapter('python');
    expect(adapter.language).toBe('python');
  });

  it('returns go adapter', () => {
    const adapter = getAdapter('go');
    expect(adapter.language).toBe('go');
    expect(adapter.fileExtensions).toContain('.go');
  });

  it('returns php adapter', () => {
    const adapter = getAdapter('php');
    expect(adapter.language).toBe('php');
    expect(adapter.fileExtensions).toContain('.php');
  });
});

// ── getSupportedExtensions ──────────────────────────────────────

describe('getSupportedExtensions', () => {
  it('returns all supported extensions', () => {
    const exts = getSupportedExtensions();
    expect(exts).toContain('.js');
    expect(exts).toContain('.ts');
    expect(exts).toContain('.py');
    expect(exts).toContain('.tsx');
    expect(exts).toContain('.jsx');
    expect(exts).toContain('.go');
    expect(exts).toContain('.php');
  });
});

// ── parse ────────────────────────────────────────────────────────

describe('parse', () => {
  it('returns ASTree with root node', async () => {
    const tree = await parse('const x = 1;', 'javascript');
    expect(tree.root).toBeDefined();
    expect(tree.language).toBe('javascript');
    expect(tree.source).toBe('const x = 1;');
  });

  it('root node has rawType "program"', async () => {
    const tree = await parse('let a = 1;', 'javascript');
    expect(tree.root.rawType).toBe('program');
    expect(tree.root.type).toBe('unknown');
  });

  it('root location spans entire source', async () => {
    const source = 'line1\nline2\nline3';
    const tree = await parse(source, 'javascript');
    expect(tree.root.location.start.line).toBe(1);
    expect(tree.root.location.end.line).toBe(3);
  });

  it('detects function calls', async () => {
    const tree = await parse('console.log("hello")', 'javascript');
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0].text).toContain('console.log');
  });

  it('parses Go source and detects call expressions', async () => {
    const source = 'package main\nfunc f() {\n\tfmt.Println("hello")\n}\n';
    const tree = await parse(source, 'go');
    expect(tree.language).toBe('go');
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0].text).toContain('fmt.Println');
  });

  it('parses Java and extracts the outer call of a chained invocation', async () => {
    const source = 'class T { Process f(String d) throws Exception { return Runtime.getRuntime().exec("ls " + d); } }';
    const tree = await parse(source, 'java');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('.exec('));
    expect(call).toBeDefined();
    expect(call!.children.some(c => c.type === 'string_concat')).toBe(true);
    const { getAdapter } = await import('../../src/parser/index.js');
    const info = getAdapter('java').extractCallInfo(call!);
    expect(info?.name).toBe('exec');
    expect(info?.object).toBe('Runtime.getRuntime()');
  });

  it('marks Go string concatenation as dynamic call argument', async () => {
    const source = 'package main\nfunc f(dir string) {\n\texec.Command("sh", "-c", "ls "+dir)\n}\n';
    const tree = await parse(source, 'go');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('exec.Command'));
    expect(call).toBeDefined();
    expect(call!.children.some(c => c.type === 'string_concat')).toBe(true);
  });

  it('parses PHP and extracts the outer call of a chained invocation', async () => {
    const source = '<?php $r = $conn->prepare($sql)->execute(); ?>';
    const tree = await parse(source, 'php');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('->execute('));
    expect(call).toBeDefined();
    const { getAdapter } = await import('../../src/parser/index.js');
    const info = getAdapter('php').extractCallInfo(call!);
    expect(info?.name).toBe('execute');
    expect(info?.object).toBe('$conn->prepare($sql)');
  });

  it('marks PHP `.` string concatenation as dynamic call argument (not `+`)', async () => {
    const source = '<?php exec("ls -la " . $dir); ?>';
    const tree = await parse(source, 'php');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.startsWith('exec('));
    expect(call).toBeDefined();
    expect(call!.children.some(c => c.type === 'string_concat')).toBe(true);
  });

  it('treats PHP interpolated encapsed_string as a dynamic template_string', async () => {
    const source = '<?php mysqli_query($conn, "SELECT * FROM users WHERE id = $id"); ?>';
    const tree = await parse(source, 'php');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('mysqli_query'));
    expect(call).toBeDefined();
    expect(call!.children.some(c => c.type === 'template_string')).toBe(true);
  });

  it('does not treat a non-interpolated PHP encapsed_string as dynamic', async () => {
    const source = '<?php mysqli_query($conn, "SELECT * FROM users"); ?>';
    const tree = await parse(source, 'php');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('mysqli_query'));
    expect(call).toBeDefined();
    expect(call!.children.some(n => n.type === 'template_string')).toBe(false);
  });

  it('normalizes PHP hardcoded credential assignments', async () => {
    const source = '<?php $password = "SuperSecret123!"; ?>';
    const tree = await parse(source, 'php');
    const creds = tree.root.children.filter(n => n.rawType === 'hardcoded_credential');
    expect(creds.length).toBeGreaterThanOrEqual(1);
  });

  it('detects template literals with expressions', async () => {
    const tree = await parse('const s = `hello ${name}`;', 'javascript');
    const templates = tree.root.children.filter(n => n.type === 'template_string');
    expect(templates.length).toBeGreaterThanOrEqual(1);
  });

  it('detects multiline dynamic call arguments', async () => {
    const tree = await parse(
      'pool.query(\n  `SELECT * FROM users WHERE id = ${userId}`\n)',
      'typescript',
    );
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0].children.some(n => n.type === 'template_string')).toBe(true);
  });

  it('detects string concatenation', async () => {
    const tree = await parse('const q = "SELECT " + userInput;', 'javascript');
    const concats = tree.root.children.filter(n => n.type === 'string_concat');
    expect(concats.length).toBeGreaterThanOrEqual(1);
  });

  it('detects Python f-strings', async () => {
    const tree = await parse('query = f"SELECT * FROM {table}"', 'python');
    const fstrings = tree.root.children.filter(n => n.rawType === 'f_string');
    expect(fstrings.length).toBeGreaterThanOrEqual(1);
  });

  it('detects multiline Python f-strings inside calls', async () => {
    const tree = await parse('os.system(\n  f"rm -rf {path}"\n)', 'python');
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0].children.some(n => n.rawType === 'f_string')).toBe(true);
  });

  it('detects hardcoded credential assignments', async () => {
    const tree = await parse('const password = "secret123";', 'javascript');
    const creds = tree.root.children.filter(n => n.rawType === 'hardcoded_credential');
    expect(creds.length).toBeGreaterThanOrEqual(1);
  });

  it('sets parent references on children', async () => {
    const tree = await parse('foo()', 'javascript');
    for (const child of tree.root.children) {
      expect(child.parent).toBe(tree.root);
    }
  });

  it('handles empty source', async () => {
    const tree = await parse('', 'javascript');
    expect(tree.root.children.length).toBe(0);
  });

  it('handles multiline source', async () => {
    const source = 'const a = 1;\nconst b = 2;\nconsole.log(a + b);';
    const tree = await parse(source, 'javascript');
    expect(tree.root.children.length).toBeGreaterThan(0);
  });
});

// ── parse precision & compatibility ──────────────────────────────

describe('parse precision & compatibility', () => {
  it('reports accurate 1-based line numbers for nodes on later lines', async () => {
    const source = '// header\n// comment\n\nconst a = 1;\npool.query(`SELECT ${a}`);\n';
    const tree = await parse(source, 'typescript');
    const call = tree.root.children.find(n => n.type === 'function_call');
    expect(call).toBeDefined();
    expect(call!.location.start.line).toBe(5);
    expect(call!.location.start.column).toBe(0);
  });

  it('normalizes nested calls as separate function_call nodes', async () => {
    const tree = await parse('outer(inner(x))', 'javascript');
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    const texts = calls.map(n => n.text);
    expect(texts.some(t => t.startsWith('outer('))).toBe(true);
    expect(texts.some(t => t.startsWith('inner('))).toBe(true);
  });

  it('tolerates syntax errors without throwing (all languages)', async () => {
    await expect(parse('const x = (]{ function', 'typescript')).resolves.toBeDefined();
    await expect(parse('def broken(:\n  pass', 'python')).resolves.toBeDefined();
    await expect(parse('package main\nfunc f( {', 'go')).resolves.toBeDefined();
    await expect(parse('class T { void f( { }', 'java')).resolves.toBeDefined();
  });

  it('still detects sinks after a syntax error earlier in the file', async () => {
    const source = 'const broken = (]\neval(userInput)\n';
    const tree = await parse(source, 'javascript');
    const calls = tree.root.children.filter(n => n.type === 'function_call');
    expect(calls.some(n => n.text.startsWith('eval('))).toBe(true);
  });

  it('handles CRLF line endings with correct line numbers', async () => {
    const source = 'const a = 1;\r\nconst b = 2;\r\npool.query(`SELECT ${a}`);\r\n';
    const tree = await parse(source, 'typescript');
    const call = tree.root.children.find(n => n.type === 'function_call');
    expect(call).toBeDefined();
    expect(call!.location.start.line).toBe(3);
    expect(call!.children.some(n => n.type === 'template_string')).toBe(true);
  });

  it('handles CJK and emoji content without breaking detection', async () => {
    const source = 'const 提示 = "你好🚀";\ndb.query("SELECT * FROM 用户 WHERE name = " + 提示);\n';
    const tree = await parse(source, 'typescript');
    const call = tree.root.children.find(n => n.type === 'function_call');
    expect(call).toBeDefined();
    expect(call!.children.some(n => n.type === 'string_concat')).toBe(true);
    expect(call!.location.start.line).toBe(2);
  });

  it('normalizes Go var/const spec credentials at the parser level', async () => {
    const source = 'package main\n\nvar apiKey = "sk-live-1234567890"\nconst token = "tok-abcdef123456"\n';
    const tree = await parse(source, 'go');
    const creds = tree.root.children.filter(n => n.rawType === 'hardcoded_credential');
    expect(creds.length).toBe(2);
  });

  it('normalizes Java field credentials at the parser level', async () => {
    const source = 'class T {\n  private String password = "hunter22";\n}\n';
    const tree = await parse(source, 'java');
    const creds = tree.root.children.filter(n => n.rawType === 'hardcoded_credential');
    expect(creds.length).toBe(1);
    expect(creds[0].location.start.line).toBe(2);
  });

  it('marks Java constructor arguments with concatenation as dynamic', async () => {
    const source = 'class T { java.io.File f(String name) { return new java.io.File("/data/" + name); } }';
    const tree = await parse(source, 'java');
    const ctor = tree.root.children.find(n => n.type === 'function_call' && n.text.startsWith('new '));
    expect(ctor).toBeDefined();
    expect(ctor!.children.some(c => c.type === 'string_concat')).toBe(true);
  });
});

// ── goAdapter / javaAdapter ──────────────────────────────────────

function makeCallNode(text: string) {
  return {
    type: 'function_call' as const,
    rawType: 'call_expression',
    text,
    location: { start: { line: 1, column: 0 }, end: { line: 1, column: text.length } },
    children: [],
    parent: null,
    fields: {},
  };
}

describe('goAdapter', () => {
  it('maps Go raw types to standard types', () => {
    const adapter = getAdapter('go');
    expect(adapter.mapNodeType('call_expression')).toBe('function_call');
    expect(adapter.mapNodeType('short_var_declaration')).toBe('assignment');
    expect(adapter.mapNodeType('interpreted_string_literal')).toBe('literal');
    expect(adapter.mapNodeType('mystery_node')).toBe('unknown');
  });

  it('extracts receiver and name from package-qualified calls', () => {
    const info = getAdapter('go').extractCallInfo(makeCallNode('exec.Command("sh", "-c", cmd)'));
    expect(info?.name).toBe('Command');
    expect(info?.object).toBe('exec');
  });

  it('extracts bare function calls without an object', () => {
    const info = getAdapter('go').extractCallInfo(makeCallNode('panic("boom")'));
    expect(info?.name).toBe('panic');
    expect(info?.object).toBeNull();
  });
});

describe('javaAdapter', () => {
  it('maps Java raw types to standard types', () => {
    const adapter = getAdapter('java');
    expect(adapter.mapNodeType('method_invocation')).toBe('function_call');
    expect(adapter.mapNodeType('object_creation_expression')).toBe('function_call');
    expect(adapter.mapNodeType('variable_declarator')).toBe('assignment');
    expect(adapter.mapNodeType('mystery_node')).toBe('unknown');
  });

  it('strips the new keyword from constructor callees', () => {
    const info = getAdapter('java').extractCallInfo(makeCallNode('new ProcessBuilder("sh", "-c", cmd)'));
    expect(info?.name).toBe('ProcessBuilder');
    expect(info?.object).toBeNull();
  });

  it('keeps the package qualifier as the object for qualified constructors', () => {
    const info = getAdapter('java').extractCallInfo(makeCallNode('new java.io.File("/data/" + name)'));
    expect(info?.name).toBe('File');
    expect(info?.object).toBe('java.io');
  });

  it('resolves the outer argument list of chained invocations', () => {
    const info = getAdapter('java').extractCallInfo(makeCallNode('Runtime.getRuntime().exec("ls " + dir)'));
    expect(info?.name).toBe('exec');
    expect(info?.object).toBe('Runtime.getRuntime()');
  });
});

describe('phpAdapter', () => {
  it('maps PHP raw types to standard types', () => {
    const adapter = getAdapter('php');
    expect(adapter.mapNodeType('function_call_expression')).toBe('function_call');
    expect(adapter.mapNodeType('member_call_expression')).toBe('function_call');
    expect(adapter.mapNodeType('scoped_call_expression')).toBe('function_call');
    expect(adapter.mapNodeType('assignment_expression')).toBe('assignment');
    expect(adapter.mapNodeType('mystery_node')).toBe('unknown');
  });

  it('extracts bare function calls without an object', () => {
    const info = getAdapter('php').extractCallInfo(makeCallNode('mysqli_query($conn, $sql)'));
    expect(info?.name).toBe('mysqli_query');
    expect(info?.object).toBeNull();
  });

  it('splits `->` method calls into object and name', () => {
    const info = getAdapter('php').extractCallInfo(makeCallNode('$pdo->query($sql)'));
    expect(info?.name).toBe('query');
    expect(info?.object).toBe('$pdo');
  });

  it('splits `::` static calls into scope and name', () => {
    const info = getAdapter('php').extractCallInfo(makeCallNode('DB::query($sql)'));
    expect(info?.name).toBe('query');
    expect(info?.object).toBe('DB');
  });

  it('resolves the outer argument list of chained invocations', () => {
    const info = getAdapter('php').extractCallInfo(makeCallNode('$conn->prepare($sql)->execute()'));
    expect(info?.name).toBe('execute');
    expect(info?.object).toBe('$conn->prepare($sql)');
  });
});

// ── walkAST ──────────────────────────────────────────────────────

describe('walkAST', () => {
  it('visits root and all children', async () => {
    const tree = await parse('foo()\nbar()', 'javascript');
    const visited: string[] = [];
    walkAST(tree.root, {
      enter(node) {
        visited.push(node.rawType);
      },
    });
    expect(visited).toContain('program');
    expect(visited.length).toBeGreaterThan(1);
  });

  it('skips children when enter returns false', async () => {
    const tree = await parse('foo()', 'javascript');
    const visited: string[] = [];
    walkAST(tree.root, {
      enter(node) {
        visited.push(node.rawType);
        if (node.rawType === 'program') return false;
      },
    });
    expect(visited).toEqual(['program']);
  });

  it('calls leave after children', async () => {
    const tree = await parse('foo()', 'javascript');
    const leaves: string[] = [];
    walkAST(tree.root, {
      leave(node) {
        leaves.push(node.rawType);
      },
    });
    expect(leaves[leaves.length - 1]).toBe('program');
  });

  it('passes parent to visitor', async () => {
    const tree = await parse('foo()', 'javascript');
    const parents: Array<string | null> = [];
    walkAST(tree.root, {
      enter(node, parent) {
        parents.push(parent?.rawType ?? null);
      },
    });
    expect(parents[0]).toBeNull(); // root has no parent in visitor
  });
});

// ── Language Adapters ────────────────────────────────────────────

describe('javascriptAdapter', () => {
  it('maps call_expression to function_call', () => {
    expect(javascriptAdapter.mapNodeType('call_expression')).toBe('function_call');
  });

  it('maps template_literal to template_string', () => {
    expect(javascriptAdapter.mapNodeType('template_literal')).toBe('template_string');
  });

  it('maps unknown raw types to unknown', () => {
    expect(javascriptAdapter.mapNodeType('some_random_type')).toBe('unknown');
  });

  it('extracts call info from function_call node', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call_expression',
      text: 'console.log("test")',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 19 } },
      children: [],
      parent: null,
      fields: {},
    };
    const info = javascriptAdapter.extractCallInfo(node);
    expect(info).not.toBeNull();
    expect(info!.name).toBe('log');
    expect(info!.object).toBe('console');
  });

  it('returns null for non-function_call nodes', () => {
    const node = {
      type: 'assignment' as const,
      rawType: 'assignment_expression',
      text: 'x = 1',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 5 } },
      children: [],
      parent: null,
      fields: {},
    };
    expect(javascriptAdapter.extractCallInfo(node)).toBeNull();
  });

  it('handles calls without object', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call_expression',
      text: 'eval("code")',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 12 } },
      children: [],
      parent: null,
      fields: {},
    };
    const info = javascriptAdapter.extractCallInfo(node);
    expect(info!.name).toBe('eval');
    expect(info!.object).toBeNull();
  });
});

describe('typescriptAdapter', () => {
  it('has language typescript', () => {
    expect(typescriptAdapter.language).toBe('typescript');
  });

  it('shares mapNodeType with javascript adapter', () => {
    expect(typescriptAdapter.mapNodeType('call_expression')).toBe('function_call');
  });
});

describe('pythonAdapter', () => {
  it('maps call to function_call', () => {
    expect(pythonAdapter.mapNodeType('call')).toBe('function_call');
  });

  it('maps f_string to template_string', () => {
    expect(pythonAdapter.mapNodeType('f_string')).toBe('template_string');
  });

  it('maps function_definition to function_def', () => {
    expect(pythonAdapter.mapNodeType('function_definition')).toBe('function_def');
  });

  it('extracts call info from Python function call', () => {
    const node = {
      type: 'function_call' as const,
      rawType: 'call',
      text: 'os.system("ls")',
      location: { start: { line: 1, column: 0 }, end: { line: 1, column: 15 } },
      children: [],
      parent: null,
      fields: {},
    };
    const info = pythonAdapter.extractCallInfo(node);
    expect(info!.name).toBe('system');
    expect(info!.object).toBe('os');
  });
});
