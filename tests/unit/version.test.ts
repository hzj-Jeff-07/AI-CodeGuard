import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { VERSION } from '../../src/version.js';

describe('VERSION constant', () => {
  it('matches package.json so CLI/JSON/SARIF never report a stale version', () => {
    const pkg = JSON.parse(
      readFileSync(resolve(__dirname, '../../package.json'), 'utf8'),
    ) as { version: string };

    expect(VERSION).toBe(pkg.version);
  });
});
