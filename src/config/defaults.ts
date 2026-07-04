import type { CodeGuardConfig } from '../types/index.js';

export const DEFAULT_CONFIG: CodeGuardConfig = {
  scan: {
    include: ['**/*.{ts,js,py,go,java}'],
    exclude: ['node_modules', '**/*.test.*', '**/*.spec.*', 'dist', 'build'],
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
