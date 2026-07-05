import type { Node as TreeSitterNode } from 'web-tree-sitter';
import type { Language, ASTNode, ASTree, LanguageAdapter, SourceLocation } from '../types/index.js';
import { javascriptAdapter, typescriptAdapter } from './languages/javascript.js';
import { pythonAdapter } from './languages/python.js';
import { goAdapter } from './languages/go.js';
import { javaAdapter } from './languages/java.js';
import { phpAdapter } from './languages/php.js';
import { getTreeSitterRuntime } from './tree-sitter/runtime.js';

const ADAPTERS: Record<Language, LanguageAdapter> = {
  javascript: javascriptAdapter,
  typescript: typescriptAdapter,
  python: pythonAdapter,
  go: goAdapter,
  java: javaAdapter,
  php: phpAdapter,
};

const EXTENSION_MAP: Record<string, Language> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.go': 'go',
  '.java': 'java',
  '.php': 'php',
};

// `:?=` also matches Go's short variable declaration (password := "...")
const HARDCODED_CREDENTIAL_PATTERN = /\b(password|secret|api[_-]?key|token|credential)\b\s*:?=\s*['"`][^'"`]+['"`]/i;

export function detectLanguage(filePath: string): Language | null {
  const ext = filePath.slice(filePath.lastIndexOf('.'));
  return EXTENSION_MAP[ext] ?? null;
}

export function getAdapter(language: Language): LanguageAdapter {
  return ADAPTERS[language];
}

export function getSupportedExtensions(): string[] {
  return Object.keys(EXTENSION_MAP);
}

export async function parse(source: string, language: Language): Promise<ASTree> {
  const treeSitterRuntime = await getTreeSitterRuntime();
  const parser = treeSitterRuntime.createParser(language);
  let tree: { rootNode: TreeSitterNode; delete(): void } | null = null;

  try {
    tree = parser.parse(source);
    if (!tree) {
      throw new Error(`Failed to parse ${language} source`);
    }

    const children = collectRootChildren(tree.rootNode, language);
    const root = createNode('unknown', 'program', source, toLocation(tree.rootNode), children);
    attachChildren(root, children);

    return { root, language, source };
  } finally {
    tree?.delete();
    parser.delete();
  }
}

function collectRootChildren(rootNode: TreeSitterNode, language: Language): ASTNode[] {
  const nodes: ASTNode[] = [];

  walkNamedNodes(rootNode, node => {
    const normalized = normalizeStandaloneNode(node, language);
    if (normalized) {
      nodes.push(normalized);
    }
  });

  return nodes;
}

function normalizeStandaloneNode(node: TreeSitterNode, language: Language): ASTNode | null {
  if (isCallNode(node, language)) {
    return normalizeCallNode(node, language);
  }

  if (isTemplateNode(node, language)) {
    return createTemplateNode(node, language);
  }

  if (isStringConcatNode(node, language)) {
    return createStringConcatNode(node);
  }

  if (isHardcodedCredentialNode(node, language)) {
    return createNode('assignment', 'hardcoded_credential', node.text, toLocation(node));
  }

  if (isConfigLiteralNode(node, language)) {
    return createNode('unknown', node.type, node.text, toLocation(node));
  }

  return null;
}

function normalizeCallNode(node: TreeSitterNode, language: Language): ASTNode {
  const children = collectDynamicArgumentMarkers(node, language);
  const callNode = createNode('function_call', node.type, node.text, toLocation(node), children);
  attachChildren(callNode, children);
  return callNode;
}

function collectDynamicArgumentMarkers(node: TreeSitterNode, language: Language): ASTNode[] {
  const argumentsNode = node.childForFieldName('arguments');
  if (!argumentsNode) {
    return [];
  }

  const markers: ASTNode[] = [];

  walkNamedNodes(argumentsNode, descendant => {
    if (isTemplateNode(descendant, language)) {
      markers.push(createTemplateNode(descendant, language));
      return;
    }

    if (isStringConcatNode(descendant, language)) {
      markers.push(createStringConcatNode(descendant));
    }
  });

  return markers;
}

function isCallNode(node: TreeSitterNode, language: Language): boolean {
  if (language === 'python') {
    return node.type === 'call';
  }

  if (language === 'java') {
    return node.type === 'method_invocation' || node.type === 'object_creation_expression';
  }

  if (language === 'php') {
    return node.type === 'function_call_expression'
      || node.type === 'member_call_expression'
      || node.type === 'nullsafe_member_call_expression'
      || node.type === 'scoped_call_expression'
      || node.type === 'object_creation_expression';
  }

  return node.type === 'call_expression' || node.type === 'new_expression';
}

function isTemplateNode(node: TreeSitterNode, language: Language): boolean {
  if (language === 'python') {
    return node.type === 'f_string' || (node.type === 'string' && node.descendantsOfType('interpolation').length > 0);
  }

  if (language === 'php') {
    // Every double-quoted PHP string parses as `encapsed_string`, even
    // without interpolation — only flag it as dynamic when it actually
    // has a non-text child (a `$var` or `{$expr}` interpolation).
    return node.type === 'encapsed_string'
      && node.namedChildren.some(child => child.type !== 'string_content');
  }

  return node.type === 'template_string' || node.type === 'template_literal';
}

function isStringConcatNode(node: TreeSitterNode, language: Language): boolean {
  if (language === 'python') {
    return node.type === 'binary_operator' && node.text.includes('+') && hasStringLikeDescendant(node, language);
  }

  // PHP's concatenation operator is `.`, not `+`.
  if (language === 'php') {
    return node.type === 'binary_expression' && node.text.includes('.') && hasStringLikeDescendant(node, language);
  }

  return node.type === 'binary_expression' && node.text.includes('+') && hasStringLikeDescendant(node, language);
}

function hasStringLikeDescendant(node: TreeSitterNode, language: Language): boolean {
  if (isStringLiteralLikeNode(node, language)) {
    return true;
  }

  return node.namedChildren.some(child => hasStringLikeDescendant(child, language));
}

function isStringLiteralLikeNode(node: TreeSitterNode, language: Language): boolean {
  if (language === 'python') {
    return node.type === 'string' || node.type === 'f_string';
  }

  if (language === 'go') {
    return node.type === 'interpreted_string_literal' || node.type === 'raw_string_literal';
  }

  if (language === 'java') {
    return node.type === 'string_literal';
  }

  if (language === 'php') {
    return node.type === 'string' || node.type === 'encapsed_string';
  }

  return node.type === 'string' || node.type === 'template_string' || node.type === 'template_literal';
}

function isHardcodedCredentialNode(node: TreeSitterNode, language: Language): boolean {
  if (!isAssignmentLikeNode(node, language)) {
    return false;
  }

  return HARDCODED_CREDENTIAL_PATTERN.test(node.text);
}

// CG-050 (security misconfiguration) matches on raw node text, but Stage 1
// only normalizes call/template/concat/credential nodes into the tree. Go
// misconfigurations like `&tls.Config{InsecureSkipVerify: true}` are struct
// literals, not calls, so they'd never reach the rule without this.
function isConfigLiteralNode(node: TreeSitterNode, language: Language): boolean {
  return language === 'go' && node.type === 'composite_literal';
}

function isAssignmentLikeNode(node: TreeSitterNode, language: Language): boolean {
  if (language === 'python') {
    return node.type === 'assignment';
  }

  if (language === 'go') {
    // spec nodes (not the wrapping declarations) so each binding matches once
    return node.type === 'short_var_declaration'
      || node.type === 'assignment_statement'
      || node.type === 'var_spec'
      || node.type === 'const_spec';
  }

  return node.type === 'variable_declarator' || node.type === 'assignment_expression';
}

function createTemplateNode(node: TreeSitterNode, language: Language): ASTNode {
  return createNode('template_string', language === 'python' ? 'f_string' : node.type, node.text, toLocation(node));
}

function createStringConcatNode(node: TreeSitterNode): ASTNode {
  return createNode('string_concat', node.type, node.text, toLocation(node));
}

function createNode(
  type: ASTNode['type'],
  rawType: string,
  text: string,
  location: SourceLocation,
  children: ASTNode[] = [],
): ASTNode {
  return {
    type,
    rawType,
    text,
    location,
    children,
    parent: null,
    fields: {},
  };
}

function attachChildren(parent: ASTNode, children: ASTNode[]): void {
  for (const child of children) {
    child.parent = parent;
  }
}

function toLocation(node: TreeSitterNode): SourceLocation {
  return {
    start: {
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
    },
    end: {
      line: node.endPosition.row + 1,
      column: node.endPosition.column,
    },
  };
}

function walkNamedNodes(node: TreeSitterNode, visit: (node: TreeSitterNode) => void): void {
  for (const child of node.namedChildren) {
    visit(child);
    walkNamedNodes(child, visit);
  }
}
