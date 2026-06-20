import { describe, it, expect } from 'vitest';
import { runAllTests, frequencyTest, runsTest } from './nist-tests';

describe('NIST SP 800-22 statistical tests', () => {
  it('a high-quality random sequence passes all four tests', () => {
    const bytes = new Uint8Array(125_000); // 1,000,000 bits
    for (let off = 0; off < bytes.length; off += 65_536) {
      crypto.getRandomValues(bytes.subarray(off, Math.min(off + 65_536, bytes.length)));
    }
    const results = runAllTests(bytes);
    for (const r of results) {
      expect(r.passed, `${r.name}: p=${r.pValue}`).toBe(true);
    }
  });

  it('an all-zero sequence is correctly flagged as non-random', () => {
    const zeros = new Uint8Array(125_000);
    // Monobit: all zeros is the most extreme bias possible → p-value ≈ 0.
    expect(frequencyTest(zeros).passed).toBe(false);
    // Runs: a single run also fails.
    expect(runsTest(zeros).passed).toBe(false);
  });
});
