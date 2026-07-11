import type { CodeGuardConfig } from '../types/index.js';

export const DEFAULT_CONFIG: CodeGuardConfig = {
  scan: {
    include: ['**/*.{ts,js,py,go,java,php}'],
    // *.min.js: minified bundles are unreadable vendored artifacts — rule
    // hits inside them are pure noise (nobody fixes a minified line), and a
    // single such file can dominate a scan's findings.
    exclude: ['node_modules', '**/*.test.*', '**/*.spec.*', '**/*.min.js', 'dist', 'build'],
  },
  rules: {
    preset: 'owasp-top-10',
    disable: [],
  },
  llm: {
    provider: 'claude',
    model: 'claude-sonnet-5',
    maxConcurrency: 5,
  },
  output: {
    format: 'text',
  },
  cache: {
    enabled: false,
    directory: '.codeguard-cache',
    ttl: 86400,
  },
};
