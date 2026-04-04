/**
 * Known Answer Test (KAT) Runner
 *
 * Runs HMAC-DRBG against NIST CAVS test vectors to verify
 * implementation correctness.
 *
 * Test structure (per CAVS format):
 *   1. Instantiate with EntropyInput, Nonce, PersonalizationString
 *   2. Reseed with EntropyInputReseed, AdditionalInputReseed
 *   3. First Generate call (output discarded)
 *   4. Second Generate call — compare output to ReturnedBits
 */

import type { KATResult, KATVector } from '../types/drbg';
import { hmacDrbgInstantiate, hmacDrbgReseed, hmacDrbgGenerate } from '../algorithms/hmac-drbg';
import { HMAC_DRBG_VECTORS } from './hmac-drbg-vectors';

/** Convert hex string to Uint8Array */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Run a single KAT vector
 */
async function runVector(vector: KATVector): Promise<KATResult> {
  try {
    const entropyInput = hexToBytes(vector.entropyInput);
    const nonce = hexToBytes(vector.nonce);
    const personalization = hexToBytes(vector.personalization);
    const entropyReseed = hexToBytes(vector.entropyInputReseed);
    const additionalReseed = hexToBytes(vector.additionalInputReseed);
    const additionalInput1 = hexToBytes(vector.additionalInput1);
    const additionalInput2 = hexToBytes(vector.additionalInput2);
    const expectedBits = vector.returnedBits.toLowerCase();

    // Step 1: Instantiate
    let state = await hmacDrbgInstantiate(
      entropyInput, nonce, personalization, 256
    );

    // Step 2: Reseed
    state = await hmacDrbgReseed(state, entropyReseed, additionalReseed);

    // Step 3: First generate (discard output)
    const requestedBytes = expectedBits.length / 2;
    const requestedBits = requestedBytes * 8;
    const gen1 = await hmacDrbgGenerate(state, requestedBits, additionalInput1);
    state = gen1.state;

    // Step 4: Second generate — compare to expected
    const gen2 = await hmacDrbgGenerate(state, requestedBits, additionalInput2);
    const actualHex = bytesToHex(gen2.result.bytes);

    const passed = actualHex === expectedBits;
    let mismatchAt: number | undefined;
    if (!passed) {
      for (let i = 0; i < actualHex.length; i++) {
        if (actualHex[i] !== expectedBits[i]) {
          mismatchAt = i;
          break;
        }
      }
    }

    return {
      vectorId: vector.id,
      passed,
      expected: expectedBits,
      actual: actualHex,
      mismatchAt,
    };
  } catch (err) {
    return {
      vectorId: vector.id,
      passed: false,
      expected: vector.returnedBits,
      actual: `ERROR: ${err instanceof Error ? err.message : String(err)}`,
      mismatchAt: 0,
    };
  }
}

/**
 * Run all HMAC-DRBG KAT vectors
 */
export async function runAllKATVectors(): Promise<KATResult[]> {
  const results: KATResult[] = [];
  for (const vector of HMAC_DRBG_VECTORS) {
    results.push(await runVector(vector));
  }
  return results;
}

/**
 * Run KAT vectors and return summary
 */
export async function runKATSummary(): Promise<{
  total: number;
  passed: number;
  failed: number;
  results: KATResult[];
}> {
  const results = await runAllKATVectors();
  const passed = results.filter(r => r.passed).length;
  return {
    total: results.length,
    passed,
    failed: results.length - passed,
    results,
  };
}
