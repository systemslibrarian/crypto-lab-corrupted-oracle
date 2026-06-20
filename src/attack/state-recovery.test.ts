import { describe, it, expect } from 'vitest';
import {
  NIST_P, DEMO_Q, DEMO_BACKDOOR_D,
  scalarMult, scalarMultQ, dualEcGenerate, bigintToBytes,
  dualEcDrbgInstantiate, dualEcDrbgGenerate,
} from '../algorithms/dual-ec-drbg';
import { recoverState } from './state-recovery';

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

describe('Backdoor state recovery', () => {
  // Fast: the core trapdoor step, with no brute force, on a known internal state.
  it('d · (s·Q) = s·P, so the output point inverts straight back to the next state', () => {
    const s0 = 999n;
    const s1 = dualEcGenerate(s0, NIST_P, DEMO_Q).nextState; // s1 = x(s0·P)
    const R1 = scalarMultQ(s1, DEMO_Q);                      // the point behind output₁
    const recovered = scalarMult(DEMO_BACKDOOR_D, R1).x;     // d·R1 = s1·P → its x is s₂
    const s2 = dualEcGenerate(s1, NIST_P, DEMO_Q).nextState; // x(s1·P)
    expect(recovered).toBe(s2);
  });

  // End-to-end: brute-force the truncated bits and predict future output. The
  // full code path runs (lift candidate x → curve, d·R, verify, predict). We
  // pick a seed whose true 16 high bits are small so the search converges in a
  // handful of candidates — this keeps the TEST fast. In the live demo the match
  // is uniformly placed, so the search averages ~32,768 candidates.
  it('recovers state from two outputs and predicts the generator exactly', async () => {
    // Seed 10549 yields a first block whose 16 truncated high bits are zero, so
    // the brute force matches on the very first candidate — this keeps the test
    // fast while still exercising the entire path (lift x → curve, d·R, verify,
    // predict). In the live demo the match is uniformly placed (~32,768 tries).
    const r1 = dualEcGenerate(10549n, NIST_P, DEMO_Q);
    const r2 = dualEcGenerate(r1.nextState, NIST_P, DEMO_Q);

    const result = await recoverState(
      r1.output, r2.output, DEMO_BACKDOOR_D, NIST_P, DEMO_Q, undefined, 5,
    );
    expect(result.success).toBe(true);

    // Independently advance the real generator and compare to the predictions.
    let truth = r2.nextState;
    for (const predicted of result.predictedOutputs) {
      const actual = dualEcGenerate(truth, NIST_P, DEMO_Q);
      expect(toHex(predicted)).toBe(toHex(actual.output));
      truth = actual.nextState;
    }
  }, 60_000);

  // Mirrors the UI exactly: two Generate clicks → attack → the NEXT click. The
  // recovered state must equal the generator's current state, so the attacker's
  // first prediction is precisely the user's next output. (We search for a seed
  // whose first block has small high bits so the brute force stays fast.)
  it('the attacker predicts your next Generate click (DRBG level)', async () => {
    const empty = new Uint8Array(0);
    // Entropy 87133 instantiates to a state whose first block has zero high bits,
    // so the search matches on the first candidate (fast + deterministic).
    const state = await dualEcDrbgInstantiate(bigintToBytes(87133n, 32), empty, empty, 256);

    // Two consecutive Generate clicks — the "intercepted traffic".
    let g = await dualEcDrbgGenerate(state, 240, empty, NIST_P, DEMO_Q);
    const blockA = g.result.bytes;
    g = await dualEcDrbgGenerate(g.state, 240, empty, NIST_P, DEMO_Q);
    const blockB = g.result.bytes;
    const stateAfterIntercept = g.state;

    // The attacker recovers from the two blocks alone.
    const result = await recoverState(blockA, blockB, DEMO_BACKDOOR_D, NIST_P, DEMO_Q, undefined, 3);
    expect(result.success).toBe(true);

    // The user's very next Generate equals the attacker's first prediction.
    const next = await dualEcDrbgGenerate(stateAfterIntercept, 240, empty, NIST_P, DEMO_Q);
    expect(toHex(next.result.bytes)).toBe(toHex(result.predictedOutputs[0]));
  }, 60_000);
});
