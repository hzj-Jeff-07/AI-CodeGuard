import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, stat, readdir, unlink, rmdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { FixSuggestion, LLMAnalysis } from '../types/index.js';

export interface CacheKey {
  ruleId: string;
  model: string;
  provider: string;
  snippet: string;
  context: string;
  includeFix: boolean;
}

export interface CachedAnalysis {
  confirmed: boolean;
  llmAnalysis: LLMAnalysis;
  fix?: FixSuggestion;
  inputTokens: number;
  outputTokens: number;
  cachedAt: number;
  schemaVersion: number;
}

export interface CacheStore {
  get(key: CacheKey): Promise<CachedAnalysis | null>;
  set(key: CacheKey, value: CachedAnalysis): Promise<void>;
}

const SCHEMA_VERSION = 1;

export function hashCacheKey(key: CacheKey): string {
  const payload = JSON.stringify({
    v: SCHEMA_VERSION,
    ruleId: key.ruleId,
    model: key.model,
    provider: key.provider,
    snippet: key.snippet,
    context: key.context,
    includeFix: key.includeFix,
  });
  return createHash('sha256').update(payload).digest('hex');
}

export interface FileCacheOptions {
  directory: string;
  ttlSeconds: number;
  now?: () => number;
}

export class FileCacheStore implements CacheStore {
  private readonly directory: string;
  private readonly ttlSeconds: number;
  private readonly now: () => number;

  constructor(options: FileCacheOptions) {
    this.directory = options.directory;
    this.ttlSeconds = options.ttlSeconds;
    this.now = options.now ?? (() => Date.now());
  }

  async get(key: CacheKey): Promise<CachedAnalysis | null> {
    const file = this.pathFor(key);
    try {
      const raw = await readFile(file, 'utf-8');
      const parsed = JSON.parse(raw) as CachedAnalysis;
      if (parsed.schemaVersion !== SCHEMA_VERSION) {
        return null;
      }
      if (this.isExpired(parsed.cachedAt)) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  async set(key: CacheKey, value: CachedAnalysis): Promise<void> {
    const file = this.pathFor(key);
    await mkdir(dirname(file), { recursive: true });
    const record: CachedAnalysis = {
      ...value,
      schemaVersion: SCHEMA_VERSION,
    };
    await writeFile(file, JSON.stringify(record), 'utf-8');
  }

  async prune(): Promise<number> {
    let removed = 0;
    try {
      const shards = await readdir(this.directory);
      for (const shard of shards) {
        const shardPath = join(this.directory, shard);
        let info;
        try {
          info = await stat(shardPath);
        } catch {
          continue;
        }
        if (!info.isDirectory()) continue;

        const files = await readdir(shardPath);
        for (const f of files) {
          const fp = join(shardPath, f);
          try {
            const raw = await readFile(fp, 'utf-8');
            const parsed = JSON.parse(raw) as CachedAnalysis;
            if (parsed.schemaVersion !== SCHEMA_VERSION || this.isExpired(parsed.cachedAt)) {
              await unlink(fp);
              removed += 1;
            }
          } catch {
            await unlink(fp).catch(() => undefined);
            removed += 1;
          }
        }

        const remaining = await readdir(shardPath);
        if (remaining.length === 0) {
          await rmdir(shardPath).catch(() => undefined);
        }
      }
    } catch {
      // cache directory missing — nothing to prune
    }
    return removed;
  }

  private pathFor(key: CacheKey): string {
    const hash = hashCacheKey(key);
    return join(this.directory, hash.slice(0, 2), `${hash}.json`);
  }

  private isExpired(cachedAt: number): boolean {
    if (this.ttlSeconds <= 0) return false;
    const ageMs = this.now() - cachedAt;
    return ageMs > this.ttlSeconds * 1000;
  }
}

export class MemoryCacheStore implements CacheStore {
  private readonly store = new Map<string, CachedAnalysis>();

  async get(key: CacheKey): Promise<CachedAnalysis | null> {
    return this.store.get(hashCacheKey(key)) ?? null;
  }

  async set(key: CacheKey, value: CachedAnalysis): Promise<void> {
    this.store.set(hashCacheKey(key), {
      ...value,
      schemaVersion: SCHEMA_VERSION,
    });
  }

  size(): number {
    return this.store.size;
  }
}
