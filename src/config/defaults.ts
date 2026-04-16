import type { CodeGuardConfig } from '../types/index.js';

export const DEFAULT_CONFIG: CodeGuardConfig = {
  scan: {
    include: ['**/*.{ts,js,py}'],
    exclude: ['node_modules', '**/*.test.*', '**/*.spec.*', 'dist', 'build'],
  },
  rules: {
    preset: 'owasp-top-10',
    disable: [],
  },
  llm: {
    provider: 'claude',
    model: 'claude-sonnet-4-6',
    maxConcurrency: 5,
  },
  output: {
    format: 'text',
  },
  cache: {
    enabled: true,
    directory: '.codeguard-cache',
    ttl: 86400,
  },
};
