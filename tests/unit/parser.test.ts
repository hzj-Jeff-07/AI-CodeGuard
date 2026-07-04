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

  it('marks Go string concatenation as dynamic call argument', async () => {
    const source = 'package main\nfunc f(dir string) {\n\texec.Command("sh", "-c", "ls "+dir)\n}\n';
    const tree = await parse(source, 'go');
    const call = tree.root.children.find(n => n.type === 'function_call' && n.text.includes('exec.Command'));
    expect(call).toBeDefined();
    expect(call!.children.some(c => c.type === 'string_concat')).toBe(true);
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
