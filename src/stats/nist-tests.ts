/**
 * NIST SP 800-22 Rev 1a — Statistical Test Suite (Subset)
 *
 * Implements 4 of the 15 tests from the NIST randomness test suite.
 * These tests evaluate the randomness of binary sequences.
 *
 * KEY POINT: Dual_EC_DRBG passes all four of these tests even with
 * the backdoor active. Statistical tests CANNOT detect the Dual_EC
 * backdoor. The backdoor is structural, not statistical.
 */

import type { StatTestResult } from '../types/drbg';

/**
 * Complementary error function approximation
 * Used for computing p-values from normal distribution
 */
function erfc(x: number): number {
  // Approximation using Horner's method (Abramowitz and Stegun 7.1.26)
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const result = poly * Math.exp(-x * x);
  return x >= 0 ? result : 2 - result;
}

/**
 * Incomplete gamma function (lower) approximation
 * For the longest-run test chi-square computation
 */
function gammainc(a: number, x: number): number {
  // Series expansion for lower incomplete gamma
  if (x < 0) return 0;
  if (x === 0) return 0;

  let sum = 0;
  let term = 1 / a;
  sum = term;
  for (let n = 1; n < 200; n++) {
    term *= x / (a + n);
    sum += term;
    if (Math.abs(term) < 1e-12 * Math.abs(sum)) break;
  }
  return sum * Math.exp(-x + a * Math.log(x) - lgamma(a));
}

/** Log-gamma function (Stirling's approximation + Lanczos) */
function lgamma(x: number): number {
  const g = 7;
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (x < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  }
  x -= 1;
  let a = c[0];
  const t = x + g + 0.5;
  for (let i = 1; i < g + 2; i++) {
    a += c[i] / (x + i);
  }
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

/** Upper incomplete gamma function Q(a,x) = 1 - P(a,x) */
function gammaincc(a: number, x: number): number {
  return 1 - gammainc(a, x);
}

/**
 * Convert Uint8Array to bit array (each element is 0 or 1)
 */
function toBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 7; bit >= 0; bit--) {
      bits.push((bytes[i] >> bit) & 1);
    }
  }
  return bits;
}

/**
 * §2.1 — Frequency (Monobit) Test
 *
 * Purpose: Determine whether the number of ones and zeros in a sequence
 * are approximately the same as would be expected for a truly random sequence.
 *
 * The test statistic is S_obs = |S_n| / sqrt(n) where S_n = sum(2*b_i - 1).
 * P-value = erfc(S_obs / sqrt(2)).
 */
export function frequencyTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;

  // S_n = sum of (2*bit - 1) for all bits
  let sn = 0;
  for (let i = 0; i < n; i++) {
    sn += 2 * bits[i] - 1;
  }

  const sObs = Math.abs(sn) / Math.sqrt(n);
  const pValue = erfc(sObs / Math.sqrt(2));
  const passed = pValue > 0.01;

  return {
    name: 'Frequency (Monobit)',
    pValue,
    passed,
    detail: `S_n=${sn}, S_obs=${sObs.toFixed(4)}, n=${n}`,
  };
}

/**
 * §2.2 — Frequency Test within a Block
 *
 * Purpose: Determine whether the frequency of ones in M-bit blocks is
 * approximately M/2, as would be expected under randomness.
 *
 * Divide sequence into N blocks of M bits.
 * π_i = proportion of ones in block i.
 * χ² = 4M * Σ(π_i - 0.5)²
 * P-value = igamc(N/2, χ²/2)
 */
export function blockFrequencyTest(bytes: Uint8Array, blockSize: number = 128): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;
  const M = blockSize;
  const N = Math.floor(n / M);

  if (N === 0) {
    return {
      name: 'Block Frequency',
      pValue: 0,
      passed: false,
      detail: 'Insufficient data for block size',
    };
  }

  let chiSquared = 0;
  for (let i = 0; i < N; i++) {
    let onesCount = 0;
    for (let j = 0; j < M; j++) {
      onesCount += bits[i * M + j];
    }
    const pi = onesCount / M;
    chiSquared += (pi - 0.5) * (pi - 0.5);
  }
  chiSquared *= 4 * M;

  const pValue = gammaincc(N / 2, chiSquared / 2);
  const passed = pValue > 0.01;

  return {
    name: 'Block Frequency',
    pValue,
    passed,
    detail: `M=${M}, N=${N}, χ²=${chiSquared.toFixed(4)}`,
  };
}

/**
 * §2.3 — Runs Test
 *
 * Purpose: Determine whether the number of runs (uninterrupted sequences
 * of identical bits) is as expected for a random sequence.
 *
 * Pre-test: frequency test (|π - 0.5| < τ where τ = 2/√n)
 * V_n(obs) = number of runs (transitions + 1)
 * P-value = erfc(|V_n(obs) - 2nπ(1-π)| / (2√(2n)·π·(1-π)))
 */
export function runsTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;

  // Pre-requisite: compute π (proportion of ones)
  let onesCount = 0;
  for (let i = 0; i < n; i++) {
    onesCount += bits[i];
  }
  const pi = onesCount / n;

  // Pre-test
  const tau = 2 / Math.sqrt(n);
  if (Math.abs(pi - 0.5) >= tau) {
    return {
      name: 'Runs',
      pValue: 0,
      passed: false,
      detail: `Pre-test failed: π=${pi.toFixed(4)}, τ=${tau.toFixed(4)}`,
    };
  }

  // Count runs (V_n)
  let vObs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) {
      vObs++;
    }
  }

  const numerator = Math.abs(vObs - 2 * n * pi * (1 - pi));
  const denominator = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const pValue = erfc(numerator / denominator);
  const passed = pValue > 0.01;

  return {
    name: 'Runs',
    pValue,
    passed,
    detail: `π=${pi.toFixed(4)}, V_obs=${vObs}, n=${n}`,
  };
}

/**
 * §2.4 — Longest Run of Ones in a Block
 *
 * Purpose: Determine whether the longest run of ones within M-bit blocks
 * is consistent with the expected longest run for a random sequence.
 *
 * For n ≥ 6272: M=10000, K=6, N=⌊n/M⌋
 * For 128 ≤ n < 6272: M=128, K=5, N=⌊n/M⌋
 * For n < 128: M=8, K=3, N=⌊n/M⌋
 */
export function longestRunTest(bytes: Uint8Array): StatTestResult {
  const bits = toBits(bytes);
  const n = bits.length;

  let M: number, K: number, piValues: number[];

  if (n >= 750000) {
    M = 10000;
    K = 6;
    piValues = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727];
  } else if (n >= 6272) {
    M = 128;
    K = 5;
    piValues = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124];
  } else {
    M = 8;
    K = 3;
    piValues = [0.2148, 0.3672, 0.2305, 0.1875];
  }

  const N = Math.floor(n / M);
  if (N === 0) {
    return {
      name: 'Longest Run of Ones',
      pValue: 0,
      passed: false,
      detail: 'Insufficient data',
    };
  }

  // Count longest runs in each block
  const nu = new Array(K + 1).fill(0);

  for (let i = 0; i < N; i++) {
    let maxRun = 0;
    let currentRun = 0;
    for (let j = 0; j < M; j++) {
      if (bits[i * M + j] === 1) {
        currentRun++;
        if (currentRun > maxRun) maxRun = currentRun;
      } else {
        currentRun = 0;
      }
    }

    // Map longest run to category
    let category: number;
    if (M === 8) {
      if (maxRun <= 1) category = 0;
      else if (maxRun === 2) category = 1;
      else if (maxRun === 3) category = 2;
      else category = 3;
    } else if (M === 128) {
      if (maxRun <= 4) category = 0;
      else if (maxRun === 5) category = 1;
      else if (maxRun === 6) category = 2;
      else if (maxRun === 7) category = 3;
      else if (maxRun === 8) category = 4;
      else category = 5;
    } else {
      // M === 10000
      if (maxRun <= 10) category = 0;
      else if (maxRun === 11) category = 1;
      else if (maxRun === 12) category = 2;
      else if (maxRun === 13) category = 3;
      else if (maxRun === 14) category = 4;
      else if (maxRun === 15) category = 5;
      else category = 6;
    }

    nu[category]++;
  }

  // Chi-squared statistic
  let chiSquared = 0;
  for (let i = 0; i <= K; i++) {
    const expected = N * piValues[i];
    chiSquared += ((nu[i] - expected) * (nu[i] - expected)) / expected;
  }

  const pValue = gammaincc(K / 2, chiSquared / 2);
  const passed = pValue > 0.01;

  return {
    name: 'Longest Run of Ones',
    pValue,
    passed,
    detail: `M=${M}, N=${N}, K=${K}, χ²=${chiSquared.toFixed(4)}`,
  };
}

/** Run all four statistical tests on a byte sequence */
export function runAllTests(bytes: Uint8Array): StatTestResult[] {
  return [
    frequencyTest(bytes),
    blockFrequencyTest(bytes),
    runsTest(bytes),
    longestRunTest(bytes),
  ];
}
