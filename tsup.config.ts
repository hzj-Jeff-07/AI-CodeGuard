import { copyFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { defineConfig } from 'tsup';

const require = createRequire(import.meta.url);
const WASM_ASSETS = [
  {
    from: require.resolve('web-tree-sitter/web-tree-sitter.wasm'),
    to: 'web-tree-sitter.wasm',
  },
  {
    from: require.resolve('tree-sitter-javascript/tree-sitter-javascript.wasm'),
    to: 'tree-sitter-javascript.wasm',
  },
  {
    from: require.resolve('tree-sitter-typescript/tree-sitter-tsx.wasm'),
    to: 'tree-sitter-tsx.wasm',
  },
  {
    from: require.resolve('tree-sitter-python/tree-sitter-python.wasm'),
    to: 'tree-sitter-python.wasm',
  },
  {
    from: require.resolve('tree-sitter-go/tree-sitter-go.wasm'),
    to: 'tree-sitter-go.wasm',
  },
  {
    from: require.resolve('tree-sitter-java/tree-sitter-java.wasm'),
    to: 'tree-sitter-java.wasm',
  },
  {
    from: require.resolve('tree-sitter-php/tree-sitter-php.wasm'),
    to: 'tree-sitter-php.wasm',
  },
];

export default defineConfig({
  entry: ['src/cli/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node18',
  banner: {
    js: '#!/usr/bin/env node',
  },
  onSuccess: async () => {
    const assetDir = join('dist', 'tree-sitter');
    await mkdir(assetDir, { recursive: true });
    await Promise.all(
      WASM_ASSETS.map(asset => copyFile(asset.from, join(assetDir, asset.to))),
    );
  },
});
