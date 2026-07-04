import { z } from 'zod';

export const ConfigSchema = z.object({
  scan: z.object({
    include: z.array(z.string()).default(['**/*.{ts,js,py,go,java}']),
    exclude: z.array(z.string()).default(['node_modules', '**/*.test.*', '**/*.spec.*', 'dist', 'build']),
  }).default({}),

  rules: z.object({
    preset: z.enum(['owasp-top-10', 'all', 'none']).default('owasp-top-10'),
    custom: z.string().optional(),
    disable: z.array(z.string()).default([]),
  }).default({}),

  llm: z.object({
    provider: z.enum(['claude', 'openai']).default('claude'),
    model: z.string().default('claude-sonnet-5'),
    apiKey: z.string().optional(),
    maxConcurrency: z.number().min(1).max(20).default(5),
    maxCostUSD: z.number().optional(),
  }).default({}),

  output: z.object({
    format: z.enum(['sarif', 'json', 'text']).default('text'),
    file: z.string().optional(),
  }).default({}),

  cache: z.object({
    enabled: z.boolean().default(false),
    directory: z.string().default('.codeguard-cache'),
    ttl: z.number().default(86400),
  }).default({}),
});

export type ParsedConfig = z.infer<typeof ConfigSchema>;
