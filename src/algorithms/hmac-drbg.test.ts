import { describe, it, expect } from 'vitest';
import { hmacDrbgInstantiate, hmacDrbgGenerate } from './hmac-drbg';
import { runKATSummary } from '../kat/runner';

describe('HMAC-DRBG', () => {
  it('passes every NIST CAVS 14.3 HMAC_DRBG(SHA-256) known-answer vector', async () => {
    const summary = await runKATSummary();
    const failures = summary.results.filter((r) => !r.passed);
    expect(failures, JSON.stringify(failures, null, 2)).toHaveLength(0);
    expect(summary.passed).toBe(summary.total);
    expect(summary.total).toBeGreaterThanOrEqual(5);
  });

  it('is deterministic for a fixed seed', async () => {
    const seed = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(16).fill(9);
    const empty = new Uint8Array(0);
    const a = await hmacDrbgInstantiate(seed, nonce, empty, 256);
    const b = await hmacDrbgInstantiate(seed, nonce, empty, 256);
    const oa = await hmacDrbgGenerate(a, 256, empty);
    const ob = await hmacDrbgGenerate(b, 256, empty);
    expect(Array.from(oa.result.bytes)).toEqual(Array.from(ob.result.bytes));
  });

  it('produces different streams for different seeds', async () => {
    const nonce = new Uint8Array(16);
    const empty = new Uint8Array(0);
    const a = await hmacDrbgInstantiate(new Uint8Array(32).fill(1), nonce, empty, 256);
    const b = await hmacDrbgInstantiate(new Uint8Array(32).fill(2), nonce, empty, 256);
    const oa = await hmacDrbgGenerate(a, 256, empty);
    const ob = await hmacDrbgGenerate(b, 256, empty);
    expect(Array.from(oa.result.bytes)).not.toEqual(Array.from(ob.result.bytes));
  });
});
