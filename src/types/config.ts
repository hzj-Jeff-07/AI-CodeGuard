
export type OutputFormat = 'sarif' | 'json' | 'text' | 'github';
export type LLMProvider = 'claude' | 'openai';

export interface ScanConfig {
  include: string[];
  exclude: string[];
}

export interface RulesConfig {
  preset: 'owasp-top-10' | 'all' | 'none';
  custom?: string;
  disable: string[];
}

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  maxConcurrency: number;
  maxCostUSD?: number;
}

export interface OutputConfig {
  format: OutputFormat;
  file?: string;
}

export interface CacheConfig {
  enabled: boolean;
  directory: string;
  ttl: number;
}

export interface CodeGuardConfig {
  scan: ScanConfig;
  rules: RulesConfig;
  llm: LLMConfig;
  output: OutputConfig;
  cache: CacheConfig;
}
