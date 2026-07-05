import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ConfigSchema } from '../../src/config/schema.js';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';

// ── ConfigSchema ────────────────────────────────────────────────

describe('ConfigSchema', () => {
  it('parses empty object with all defaults', () => {
    const config = ConfigSchema.parse({});
    expect(config.scan.include).toEqual(['**/*.{ts,js,py,go,java,php}']);
    expect(config.scan.exclude).toContain('node_modules');
    expect(config.rules.preset).toBe('owasp-top-10');
    expect(config.rules.disable).toEqual([]);
    expect(config.llm.provider).toBe('claude');
    expect(config.llm.model).toBe('claude-sonnet-5');
    expect(config.llm.maxConcurrency).toBe(5);
    expect(config.output.format).toBe('text');
    expect(config.cache.enabled).toBe(false);
    expect(config.cache.directory).toBe('.codeguard-cache');
    expect(config.cache.ttl).toBe(86400);
  });

  it('accepts valid partial config', () => {
    const config = ConfigSchema.parse({
      rules: { preset: 'all', disable: ['CG-001'] },
    });
    expect(config.rules.preset).toBe('all');
    expect(config.rules.disable).toEqual(['CG-001']);
    // Defaults should still be applied to other sections
    expect(config.scan.include).toEqual(['**/*.{ts,js,py,go,java,php}']);
  });

  it('validates preset enum', () => {
    expect(() => ConfigSchema.parse({ rules: { preset: 'invalid' } })).toThrow();
  });

  it('validates llm provider enum', () => {
    expect(() => ConfigSchema.parse({ llm: { provider: 'gemini' } })).toThrow();
  });

  it('validates output format enum', () => {
    expect(() => ConfigSchema.parse({ output: { format: 'csv' } })).toThrow();
  });

  it('validates maxConcurrency range', () => {
    expect(() => ConfigSchema.parse({ llm: { maxConcurrency: 0 } })).toThrow();
    expect(() => ConfigSchema.parse({ llm: { maxConcurrency: 21 } })).toThrow();
    const config = ConfigSchema.parse({ llm: { maxConcurrency: 10 } });
    expect(config.llm.maxConcurrency).toBe(10);
  });

  it('accepts optional fields', () => {
    const config = ConfigSchema.parse({
      llm: { apiKey: 'test-key', maxCostUSD: 5.0 },
      output: { file: 'report.json' },
      rules: { custom: './my-rules' },
    });
    expect(config.llm.apiKey).toBe('test-key');
    expect(config.llm.maxCostUSD).toBe(5.0);
    expect(config.output.file).toBe('report.json');
    expect(config.rules.custom).toBe('./my-rules');
  });
});

// ── DEFAULT_CONFIG ──────────────────────────────────────────────

describe('DEFAULT_CONFIG', () => {
  it('matches schema defaults', () => {
    const schemaDefaults = ConfigSchema.parse({});
    expect(DEFAULT_CONFIG.scan.include).toEqual(schemaDefaults.scan.include);
    expect(DEFAULT_CONFIG.rules.preset).toEqual(schemaDefaults.rules.preset);
    expect(DEFAULT_CONFIG.llm.provider).toEqual(schemaDefaults.llm.provider);
    expect(DEFAULT_CONFIG.output.format).toEqual(schemaDefaults.output.format);
    expect(DEFAULT_CONFIG.cache.enabled).toEqual(schemaDefaults.cache.enabled);
  });

  it('has expected structure', () => {
    expect(DEFAULT_CONFIG.scan).toBeDefined();
    expect(DEFAULT_CONFIG.rules).toBeDefined();
    expect(DEFAULT_CONFIG.llm).toBeDefined();
    expect(DEFAULT_CONFIG.output).toBeDefined();
    expect(DEFAULT_CONFIG.cache).toBeDefined();
  });
});

// ── loadConfig with env overrides ───────────────────────────────

describe('loadConfig env overrides', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('applies CODEGUARD_API_KEY from env', async () => {
    process.env.CODEGUARD_API_KEY = 'test-api-key-123';
    const { loadConfig } = await import('../../src/config/loader.js');
    const config = await loadConfig();
    expect(config.llm.apiKey).toBe('test-api-key-123');
  });

  it('applies ANTHROPIC_API_KEY from env', async () => {
    process.env.ANTHROPIC_API_KEY = 'anthropic-key-456';
    const { loadConfig } = await import('../../src/config/loader.js');
    const config = await loadConfig();
    expect(config.llm.apiKey).toBe('anthropic-key-456');
  });

  it('applies CODEGUARD_MODEL from env', async () => {
    process.env.CODEGUARD_MODEL = 'claude-opus-4-6';
    const { loadConfig } = await import('../../src/config/loader.js');
    const config = await loadConfig();
    expect(config.llm.model).toBe('claude-opus-4-6');
  });

  it('returns defaults when no config file found', async () => {
    const { loadConfig } = await import('../../src/config/loader.js');
    const config = await loadConfig();
    expect(config.rules.preset).toBe('owasp-top-10');
    expect(config.output.format).toBe('text');
  });
});
