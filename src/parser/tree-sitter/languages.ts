import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Language } from '../../types/index.js';

const require = createRequire(import.meta.url);
const packageRoot = findPackageRoot(dirname(fileURLToPath(import.meta.url)));

const BUNDLED_CORE_WASM_PATH = join(packageRoot, 'dist', 'tree-sitter', 'web-tree-sitter.wasm');
const BUNDLED_GRAMMAR_WASM_PATHS: Record<Language, string> = {
  javascript: join(packageRoot, 'dist', 'tree-sitter', 'tree-sitter-javascript.wasm'),
  typescript: join(packageRoot, 'dist', 'tree-sitter', 'tree-sitter-tsx.wasm'),
  python: join(packageRoot, 'dist', 'tree-sitter', 'tree-sitter-python.wasm'),
  go: join(packageRoot, 'dist', 'tree-sitter', 'tree-sitter-go.wasm'),
};

const FALLBACK_GRAMMAR_WASM_PATHS: Record<Language, string> = {
  javascript: require.resolve('tree-sitter-javascript/tree-sitter-javascript.wasm'),
  typescript: require.resolve('tree-sitter-typescript/tree-sitter-tsx.wasm'),
  python: require.resolve('tree-sitter-python/tree-sitter-python.wasm'),
  go: require.resolve('tree-sitter-go/tree-sitter-go.wasm'),
};

export function resolveCoreWasmPath(): string {
  return existsSync(BUNDLED_CORE_WASM_PATH)
    ? BUNDLED_CORE_WASM_PATH
    : require.resolve('web-tree-sitter/web-tree-sitter.wasm');
}

export function resolveGrammarWasmPath(language: Language): string {
  return existsSync(BUNDLED_GRAMMAR_WASM_PATHS[language])
    ? BUNDLED_GRAMMAR_WASM_PATHS[language]
    : FALLBACK_GRAMMAR_WASM_PATHS[language];
}

function findPackageRoot(startDir: string): string {
  let currentDir = startDir;

  while (true) {
    if (existsSync(join(currentDir, 'package.json'))) {
      return currentDir;
    }

    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) {
      throw new Error('Unable to locate package root for Tree-sitter assets');
    }

    currentDir = parentDir;
  }
}
