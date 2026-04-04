/**
 * Dual_EC_DRBG Backdoor State Recovery Attack
 *
 * This implements the real attack against Dual_EC_DRBG when the
 * attacker knows the scalar d = e⁻¹ mod n, where Q = e·P.
 *
 * Per SP 800-90A §10.3.1, each generate call computes:
 *   s_new = (s · P).x        — state update
 *   r     = (s_new · Q).x    — output value
 *   output = truncate(r)     — drop high 16 bits
 *
 * Attack algorithm:
 *   1. Observe output₁ (30 bytes = 240 bits of r₁, missing high 16 bits)
 *      where r₁ = (s₁ · Q).x, and s₁ = (s₀ · P).x
 *   2. Try all 2¹⁶ = 65,536 possible completions of the x-coordinate
 *   3. For each candidate x, recover y on P-256 → candidate point R₁ = s₁·Q
 *   4. Compute d · R₁ = d·(s₁·Q) = s₁·(d·Q) = s₁·P
 *      because d·Q = d·(e·P) = (d·e)·P = P  (since d = e⁻¹)
 *   5. (s₁·P).x = s₂ (the next state!)
 *   6. Verify: compute (s₂·Q).x, truncate, compare to output₂
 *   7. Once confirmed, predict all future outputs
 *
 * KEY INSIGHT: Step 4 is what makes this a backdoor. Without knowing d,
 * you cannot go from the output point R₁ = s₁·Q back to s₁·P.
 * The discrete log problem protects the relationship — unless you're
 * the entity that chose Q in the first place.
 */

import type { ECPoint, AttackResult, AttackEventHandler } from '../types/drbg';
import { recoverY, scalarMult, bytesToBigint, bigintToBytes, dualEcGenerate } from '../algorithms/dual-ec-drbg';

/**
 * Recover Dual_EC_DRBG state from two consecutive output blocks
 *
 * @param output1 - First 30-byte output block (truncated r₁)
 * @param output2 - Second 30-byte output block (for verification)
 * @param backdoorD - d = e⁻¹ mod n — THE backdoor secret (P = d·Q)
 * @param P - The P point
 * @param Q - The Q point
 * @param onEvent - Event handler for progress updates
 * @param predictCount - Number of future outputs to predict
 */
export async function recoverState(
  output1: Uint8Array,
  output2: Uint8Array,
  backdoorD: bigint,
  P: ECPoint,
  Q: ECPoint,
  onEvent?: AttackEventHandler,
  predictCount: number = 10
): Promise<AttackResult> {
  const totalCandidates = 65536;
  let candidatesTried = 0;

  // output1 is the low 30 bytes of the 32-byte x-coordinate of R₁ = s₁·Q
  // We need to try all 2^16 = 65536 possible high 2-byte prefixes
  const output1Bigint = bytesToBigint(output1);

  for (let highBits = 0; highBits < totalCandidates; highBits++) {
    candidatesTried++;

    // Reconstruct candidate x-coordinate of R₁
    const candidateX = (BigInt(highBits) << 240n) | output1Bigint;

    // Try to recover y on the curve
    const ys = recoverY(candidateX);
    if (ys === null) {
      // This x is not on the curve — skip
      if (candidatesTried % 1000 === 0 && onEvent) {
        onEvent({
          type: 'progress',
          candidatesTried,
          totalCandidates,
        });
      }
      continue;
    }

    // Try both possible y values
    for (const candidateY of ys) {
      const candidateR: ECPoint = { x: candidateX, y: candidateY };

      // THE BACKDOOR STEP:
      // Compute d · R₁ = d · (s₁ · Q) = s₁ · (d · Q) = s₁ · P
      // This works because d · Q = d · (e · P) = (d·e) · P = 1 · P = P
      const dR = scalarMult(backdoorD, candidateR);

      // (s₁ · P).x = s₂ — the next internal state
      const candidateS2 = dR.x;

      // Verify: compute output from s₂ = (s₂ · Q).x, truncate, compare
      const verifyPoint = scalarMult(candidateS2, Q);
      const verifyR = verifyPoint.x;
      const verifyBytes = bigintToBytes(verifyR, 32);
      const verifyOutput = verifyBytes.slice(2); // truncate high 16 bits

      if (arraysEqual(verifyOutput, output2)) {
        // STATE RECOVERED using the backdoor!
        if (onEvent) {
          onEvent({
            type: 'state_recovered',
            candidatesTried,
            totalCandidates,
            recoveredState: candidateS2.toString(16),
          });
        }

        // Predict future outputs from recovered state s₂
        const predictedOutputs: Uint8Array[] = [];
        const actualOutputs: Uint8Array[] = [];
        let predictState = candidateS2;

        for (let i = 0; i < predictCount; i++) {
          const predicted = dualEcGenerate(predictState, P, Q);
          predictedOutputs.push(predicted.output);
          predictState = predicted.nextState;

          if (onEvent) {
            onEvent({
              type: 'prediction',
              candidatesTried,
              totalCandidates,
              predictedOutput: toHex(predicted.output),
            });
          }
        }

        return {
          success: true,
          recoveredState: candidateS2,
          candidatesTried,
          predictedOutputs,
          actualOutputs,
          match: true,
        };
      }
    }

    // Progress update every 1000 candidates
    if (candidatesTried % 1000 === 0 && onEvent) {
      onEvent({
        type: 'progress',
        candidatesTried,
        totalCandidates,
      });

      // Yield to event loop periodically to avoid blocking UI
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }

  // Attack failed — no candidate matched
  return {
    success: false,
    recoveredState: null,
    candidatesTried,
    predictedOutputs: [],
    actualOutputs: [],
    match: false,
  };
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
