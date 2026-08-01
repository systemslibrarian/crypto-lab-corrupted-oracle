import { describe, it, expect } from 'vitest';
import { runAllTests, frequencyTest, runsTest, blockFrequencyTest } from './nist-tests';

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

  // The failing tail of Block Frequency used to be unreachable. gammainc's
  // series was truncated at 200 terms, which for a large chi-squared returned a
  // far-too-small P(a,x); Q = 1 - P then came back as exactly 1, so the most
  // non-random input possible was reported as "PASS (p=1.000000)".
  it('Block Frequency fails an all-zero sequence instead of reporting p=1', () => {
    const zeros = new Uint8Array(125_000);
    const result = blockFrequencyTest(zeros);
    expect(result.passed).toBe(false);
    expect(result.pValue).toBeLessThan(1e-10);
    expect(Number.isNaN(result.pValue)).toBe(false);
  });

  it('Block Frequency p-values stay inside [0,1] across the whole chi-squared range', () => {
    // A sweep from perfectly balanced blocks (χ²=0) to maximally skewed ones,
    // covering both sides of the series/continued-fraction crossover at x=a+1.
    for (const fill of [0x00, 0x0f, 0x33, 0x55, 0x77, 0xaa, 0xf0, 0xff]) {
      const bytes = new Uint8Array(1024).fill(fill);
      const { pValue, name } = blockFrequencyTest(bytes);
      expect(Number.isFinite(pValue), `${name} fill=${fill}: p=${pValue}`).toBe(true);
      expect(pValue, `${name} fill=${fill}`).toBeGreaterThanOrEqual(0);
      expect(pValue, `${name} fill=${fill}`).toBeLessThanOrEqual(1);
    }
  });

  // Anchor the corrected tail on an externally-known number rather than on
  // itself. 1024 bytes at M=128 gives N=8 blocks, so the statistic has
  // N/2 = 4 → 8 degrees of freedom, where the closed form for even df is
  //   Q = e^(-x/2) · Σ_{k<4} (x/2)^k / k!
  // At χ² = 15.5 that is 0.05012205. We build blocks whose ones-counts deviate
  // from 64 by exactly (20, 8, 4, 4, 0, 0, 0, 0), since
  //   χ² = Σ (k_i − 64)² / 32 = (400+64+16+16)/32 = 15.5.
  it('agrees with the closed-form chi-squared upper tail at 8 df', () => {
    const deviations = [20, 8, 4, 4, 0, 0, 0, 0];
    const bytes = new Uint8Array(128); // 1024 bits = exactly 8 blocks of M=128
    deviations.forEach((d, block) => {
      const ones = 64 + d; // ones in this 128-bit block
      const base = block * 16;
      const fullBytes = Math.floor(ones / 8);
      for (let i = 0; i < fullBytes; i++) bytes[base + i] = 0xff;
      const rest = ones % 8;
      if (rest > 0) bytes[base + fullBytes] = (0xff << (8 - rest)) & 0xff;
    });
    const result = blockFrequencyTest(bytes);
    expect(result.detail).toContain('χ²=15.5000');
    expect(result.pValue).toBeCloseTo(0.05012205, 7);
    // 0.0501 > 0.01, so this one sits just inside PASS — which is the point:
    // the tail is now graded, not clamped to 1.
    expect(result.passed).toBe(true);
  });

  // The other end of the range: perfectly balanced blocks give χ² = 0 → p = 1.
  it('returns p = 1 for perfectly balanced blocks', () => {
    expect(blockFrequencyTest(new Uint8Array(1024).fill(0x0f)).pValue).toBeCloseTo(1, 12);
  });
});
