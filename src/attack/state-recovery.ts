/**
 * Dual_EC_DRBG Backdoor State Recovery Attack
 *
 * This implements the known attack against Dual_EC_DRBG when the
 * attacker knows the scalar e such that Q = e·P (equivalently,
 * knows d = e⁻¹ mod n such that P = d·Q).
 *
 * Attack algorithm:
 *   1. Observe output₁ (30 bytes = 240 bits of r₁.x, missing high 16 bits)
 *   2. Try all 2^16 = 65,536 possible completions of the x-coordinate
 *   3. For each candidate x, recover y on P-256 (0 or 2 solutions)
 *   4. For each candidate point R₁, compute d·R₁ = d·(s·P)
 *      If Q = e·P then d·Q = P, and d·(s·P) means we can recover s
 *      Actually: R₁ = s·P, and output is truncate(R₁.x)
 *      The next state is s₁ = (R₁.x · Q).x = (r · Q).x
 *      So from R₁ we compute s₁ = (R₁.x · Q).x
 *      Then verify by generating output from s₁ and comparing to output₂
 *   5. Once confirmed, predict future outputs
 */

import type { ECPoint, AttackResult, AttackEventHandler } from '../types/drbg';
import { recoverY, scalarMult, bytesToBigint, dualEcGenerate } from '../algorithms/dual-ec-drbg';

/**
 * Recover Dual_EC_DRBG state from two consecutive output blocks
 *
 * @param output1 - First 30-byte output block
 * @param output2 - Second 30-byte output block (for verification)
 * @param backdoorD - d = e⁻¹ mod n (the backdoor secret; P = d·Q)
 * @param P - The P point
 * @param Q - The Q point
 * @param onEvent - Event handler for progress updates
 * @param predictCount - Number of future outputs to predict
 */
export async function recoverState(
  output1: Uint8Array,
  output2: Uint8Array,
  _backdoorD: bigint,
  P: ECPoint,
  Q: ECPoint,
  onEvent?: AttackEventHandler,
  predictCount: number = 10
): Promise<AttackResult> {
  const totalCandidates = 65536;
  let candidatesTried = 0;

  // output1 is the low 30 bytes of the 32-byte x-coordinate of R₁ = s·P
  // We need to try all 2^16 = 65536 possible high 2-byte prefixes
  const output1Bigint = bytesToBigint(output1);

  for (let highBits = 0; highBits < totalCandidates; highBits++) {
    candidatesTried++;

    // Reconstruct candidate x-coordinate
    const candidateX = (BigInt(highBits) << 240n) | output1Bigint;

    // Try to recover y on the curve
    const ys = recoverY(candidateX);
    if (ys === null) {
      // This x is not on the curve
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

      // From R₁ (candidate), compute next state:
      // r = R₁.x (the full x-coordinate)
      // s₁ = (r · Q).x
      const rQ = scalarMult(candidateR.x, Q);
      const candidateS1 = rQ.x;

      // Generate output from candidate s₁ and compare to output2
      const verification = dualEcGenerate(candidateS1, P, Q);

      // Compare verification output to output2
      if (arraysEqual(verification.output, output2)) {
        // STATE RECOVERED!
        if (onEvent) {
          onEvent({
            type: 'state_recovered',
            candidatesTried,
            totalCandidates,
            recoveredState: candidateS1.toString(16),
          });
        }

        // Predict future outputs
        const predictedOutputs: Uint8Array[] = [];
        const actualOutputs: Uint8Array[] = [];
        let predictState = verification.nextState;

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
          recoveredState: candidateS1,
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
