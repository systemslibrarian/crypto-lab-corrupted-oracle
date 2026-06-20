import { describe, it, expect } from 'vitest';
import {
  P256, NIST_P, NIST_Q, DEMO_Q, DEMO_BACKDOOR_E, DEMO_BACKDOOR_D,
  scalarMult, scalarMultP, scalarMultQ, recoverY, dualEcGenerate,
} from './dual-ec-drbg';
import { POINT_AT_INFINITY } from '../types/drbg';

describe('P-256 group arithmetic', () => {
  it('the generator P and the published constant Q are both on the curve', () => {
    const pYs = recoverY(NIST_P.x);
    const qYs = recoverY(NIST_Q.x);
    expect(pYs && pYs.includes(NIST_P.y)).toBe(true);
    expect(qYs && qYs.includes(NIST_Q.y)).toBe(true);
  });

  it('has the correct group order: n · G = ∞ and (n+1) · G = G', () => {
    expect(scalarMult(P256.n, NIST_P)).toEqual(POINT_AT_INFINITY);
    const back = scalarMult(P256.n + 1n, NIST_P);
    expect(back.x).toBe(NIST_P.x);
    expect(back.y).toBe(NIST_P.y);
  });

  it('fixed-base comb agrees with the generic routine', () => {
    const scalars = [1n, 15n, 16n, 65535n, 0xabcdef12345n, DEMO_BACKDOOR_E, P256.n - 1n];
    for (const k of scalars) {
      expect(scalarMultP(k)).toEqual(scalarMult(k, NIST_P));
      expect(scalarMultQ(k, DEMO_Q)).toEqual(scalarMult(k, DEMO_Q));
    }
  });
});

describe('Dual_EC trapdoor (the backdoor relationship)', () => {
  it('DEMO_Q = e · P', () => {
    expect(scalarMult(DEMO_BACKDOOR_E, NIST_P)).toEqual(DEMO_Q);
  });

  it('d = e⁻¹ mod n, so d · Q = P — this is what lets the holder of d invert output back to state', () => {
    const dQ = scalarMult(DEMO_BACKDOOR_D, DEMO_Q);
    expect(dQ.x).toBe(NIST_P.x);
    expect(dQ.y).toBe(NIST_P.y);
  });
});

describe('Dual_EC generation', () => {
  it('is deterministic and chains state forward', () => {
    const a = dualEcGenerate(12345n, NIST_P, DEMO_Q);
    const b = dualEcGenerate(12345n, NIST_P, DEMO_Q);
    expect(Array.from(a.output)).toEqual(Array.from(b.output));
    expect(a.nextState).toBe(b.nextState);
    expect(a.output.length).toBe(30); // 240 bits per block (16 bits truncated)
  });
});
