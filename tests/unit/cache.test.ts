import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtemp, rm, readFile, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FileCacheStore,
  MemoryCacheStore,
  hashCacheKey,
  type CacheKey,
  type CachedAnalysis,
} from '../../src/cache/index.js';

function makeKey(overrides: Partial<CacheKey> = {}): CacheKey {
  return {
    ruleId: 'CG-001',
    model: 'claude-sonnet-4-6',
    provider: 'claude',
    snippet: 'db.query(`SELECT * FROM u WHERE id=${id}`)',
    context: 'function getUser(id) { ... }',
    includeFix: false,
    ...overrides,
  };
}

function makeRecord(overrides: Partial<CachedAnalysis> = {}): CachedAnalysis {
  return {
    confirmed: true,
    llmAnalysis: {
      confirmed: true,
      confidence: 0.95,
      reasoning: 'Concatenated user input into SQL.',
    },
    inputTokens: 800,
    outputTokens: 120,
    cachedAt: Date.now(),
    schemaVersion: 1,
    ...overrides,
  };
}

describe('hashCacheKey', () => {
  it('returns identical hashes for identical keys', () => {
    expect(hashCacheKey(makeKey())).toBe(hashCacheKey(makeKey()));
  });

  it('returns different hashes when any field differs', () => {
    const base = hashCacheKey(makeKey());
    expect(hashCacheKey(makeKey({ ruleId: 'CG-002' }))).not.toBe(base);
    expect(hashCacheKey(makeKey({ model: 'claude-opus-4-5' }))).not.toBe(base);
    expect(hashCacheKey(makeKey({ snippet: 'other' }))).not.toBe(base);
    expect(hashCacheKey(makeKey({ context: 'other' }))).not.toBe(base);
    expect(hashCacheKey(makeKey({ includeFix: true }))).not.toBe(base);
  });

  it('produces a 64-character sha256 hex string', () => {
    expect(hashCacheKey(makeKey())).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('MemoryCacheStore', () => {
  it('stores and retrieves records by key', async () => {
    const store = new MemoryCacheStore();
    const key = makeKey();
    const record = makeRecord();

    expect(await store.get(key)).toBeNull();
    await store.set(key, record);
    expect(await store.get(key)).toMatchObject(record);
    expect(store.size()).toBe(1);
  });

  it('treats different keys as different entries', async () => {
    const store = new MemoryCacheStore();
    await store.set(makeKey(), makeRecord());
    expect(await store.get(makeKey({ ruleId: 'CG-002' }))).toBeNull();
  });
});

describe('FileCacheStore', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'codeguard-cache-'));
    return async () => {
      await rm(dir, { recursive: true, force: true });
    };
  });

  it('returns null on cache miss', async () => {
    const store = new FileCacheStore({ directory: dir, ttlSeconds: 3600 });
    expect(await store.get(makeKey())).toBeNull();
  });

  it('persists records as JSON files under sharded directories', async () => {
    const store = new FileCacheStore({ directory: dir, ttlSeconds: 3600 });
    const key = makeKey();
    const record = makeRecord();

    await store.set(key, record);
    const fetched = await store.get(key);
    expect(fetched?.llmAnalysis.reasoning).toBe(record.llmAnalysis.reasoning);

    const hash = hashCacheKey(key);
    const expectedPath = join(dir, hash.slice(0, 2), `${hash}.json`);
    const raw = await readFile(expectedPath, 'utf-8');
    expect(JSON.parse(raw).schemaVersion).toBe(1);
  });

  it('treats expired records as cache misses', async () => {
    let now = 0;
    const store = new FileCacheStore({
      directory: dir,
      ttlSeconds: 60,
      now: () => now,
    });

    await store.set(makeKey(), makeRecord({ cachedAt: 0 }));
    now = 30 * 1000;
    expect(await store.get(makeKey())).not.toBeNull();
    now = 120 * 1000;
    expect(await store.get(makeKey())).toBeNull();
  });

  it('treats records with mismatched schema version as misses', async () => {
    const store = new FileCacheStore({ directory: dir, ttlSeconds: 3600 });
    const key = makeKey();
    const hash = hashCacheKey(key);
    const path = join(dir, hash.slice(0, 2), `${hash}.json`);
    await mkdir(join(dir, hash.slice(0, 2)), { recursive: true });
    await writeFile(path, JSON.stringify({ ...makeRecord(), schemaVersion: 999 }));
    expect(await store.get(key)).toBeNull();
  });

  it('prune removes expired records and corrupt files', async () => {
    let now = 0;
    const store = new FileCacheStore({
      directory: dir,
      ttlSeconds: 60,
      now: () => now,
    });
    await store.set(makeKey(), makeRecord({ cachedAt: 0 }));
    await store.set(makeKey({ ruleId: 'CG-002' }), makeRecord({ cachedAt: 0 }));

    const corruptHash = hashCacheKey(makeKey({ ruleId: 'CORRUPT' }));
    const corruptPath = join(dir, corruptHash.slice(0, 2), `${corruptHash}.json`);
    await mkdir(join(dir, corruptHash.slice(0, 2)), { recursive: true });
    await writeFile(corruptPath, '{ not json');

    now = 200 * 1000;
    const removed = await store.prune();
    expect(removed).toBeGreaterThanOrEqual(2);
  });

  it('survives a missing cache directory during prune', async () => {
    const store = new FileCacheStore({ directory: join(dir, 'never-created'), ttlSeconds: 60 });
    await expect(store.prune()).resolves.toBe(0);
  });

  it('disabled TTL (<=0) keeps records forever', async () => {
    let now = 0;
    const store = new FileCacheStore({
      directory: dir,
      ttlSeconds: 0,
      now: () => now,
    });
    await store.set(makeKey(), makeRecord({ cachedAt: 0 }));
    now = 365 * 24 * 3600 * 1000;
    expect(await store.get(makeKey())).not.toBeNull();
  });
});
