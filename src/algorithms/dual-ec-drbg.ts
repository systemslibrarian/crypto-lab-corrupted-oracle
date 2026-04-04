/**
 * Dual_EC_DRBG Implementation
 * Per NIST SP 800-90A Rev 1 (historical), Appendix A.1
 *
 * This implements the controversial Dual Elliptic Curve DRBG that was
 * withdrawn from the NIST standard in 2014 after revelations that the
 * NSA may have inserted a backdoor via the relationship between
 * the P and Q constants.
 *
 * P-256 (secp256r1) arithmetic is implemented from scratch using
 * bigint — no external EC libraries.
 */

import type { ECPoint } from '../types/drbg';
export type { ECPoint };
export { POINT_AT_INFINITY } from '../types/drbg';
import { POINT_AT_INFINITY } from '../types/drbg';

// ─── P-256 Curve Parameters ───────────────────────────────────────────
// From SEC 2 / NIST FIPS 186-4

export const P256 = {
  /** Field prime */
  p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  /** Curve coefficient a */
  a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
  /** Curve coefficient b */
  b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  /** Generator x */
  Gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  /** Generator y */
  Gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  /** Order of the generator */
  n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
};

// ─── NIST Constants P and Q ───────────────────────────────────────────
// Per SP 800-90A Rev 1, Appendix A.1, Table 4 (P-256)
// P is the generator point G of P-256.

export const NIST_P: ECPoint = {
  x: P256.Gx,
  y: P256.Gy,
};

/**
 * Q — the NIST-published "random" point on P-256 for Dual_EC_DRBG.
 * From SP 800-90A Appendix A.1.
 *
 * The NSA allegedly knew the discrete log relationship e such that Q = e·G.
 * Knowing e allows full state recovery from a single output block.
 *
 * IMPORTANT: These values should be verified against the actual
 * SP 800-90A document. If they differ, use the document values.
 */
export const NIST_Q: ECPoint = {
  x: BigInt('0xc97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192'),
  y: BigInt('0xb28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046'),
};

// ─── Modular Arithmetic Helpers ───────────────────────────────────────

/** Modular reduction (always non-negative) */
function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/** Modular exponentiation via binary method */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) {
      result = mod(result * base, m);
    }
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

/** Modular inverse using Fermat's little theorem (p is prime) */
function modInv(a: bigint, p: bigint): bigint {
  return modPow(a, p - 2n, p);
}

// ─── P-256 Point Operations ──────────────────────────────────────────

function isInfinity(P: ECPoint): boolean {
  return P.x === 0n && P.y === 0n;
}

/**
 * Point addition on P-256
 * Standard affine coordinate formulas
 */
export function pointAdd(P1: ECPoint, P2: ECPoint): ECPoint {
  if (isInfinity(P1)) return P2;
  if (isInfinity(P2)) return P1;

  const p = P256.p;

  if (P1.x === P2.x) {
    if (P1.y !== P2.y) {
      // P1 = -P2, result is point at infinity
      return POINT_AT_INFINITY;
    }
    // P1 == P2, use doubling
    return pointDouble(P1);
  }

  // λ = (y2 - y1) / (x2 - x1) mod p
  const dx = mod(P2.x - P1.x, p);
  const dy = mod(P2.y - P1.y, p);
  const lambda = mod(dy * modInv(dx, p), p);

  // x3 = λ² - x1 - x2 mod p
  const x3 = mod(lambda * lambda - P1.x - P2.x, p);

  // y3 = λ(x1 - x3) - y1 mod p
  const y3 = mod(lambda * (P1.x - x3) - P1.y, p);

  return { x: x3, y: y3 };
}

/**
 * Point doubling on P-256
 */
export function pointDouble(P: ECPoint): ECPoint {
  if (isInfinity(P)) return POINT_AT_INFINITY;
  if (P.y === 0n) return POINT_AT_INFINITY;

  const p = P256.p;

  // λ = (3x² + a) / (2y) mod p
  const num = mod(3n * P.x * P.x + P256.a, p);
  const den = mod(2n * P.y, p);
  const lambda = mod(num * modInv(den, p), p);

  // x3 = λ² - 2x mod p
  const x3 = mod(lambda * lambda - 2n * P.x, p);

  // y3 = λ(x - x3) - y mod p
  const y3 = mod(lambda * (P.x - x3) - P.y, p);

  return { x: x3, y: y3 };
}

/**
 * Scalar multiplication using double-and-add
 * (Left-to-right binary method)
 */
export function scalarMult(k: bigint, P: ECPoint): ECPoint {
  if (k === 0n || isInfinity(P)) return POINT_AT_INFINITY;

  k = mod(k, P256.n);
  if (k === 0n) return POINT_AT_INFINITY;

  let result: ECPoint = POINT_AT_INFINITY;
  let addend: ECPoint = { x: P.x, y: P.y };

  while (k > 0n) {
    if (k & 1n) {
      result = pointAdd(result, addend);
    }
    addend = pointDouble(addend);
    k >>= 1n;
  }

  return result;
}

/**
 * Recover y-coordinate from x on P-256
 * y² = x³ + ax + b (mod p)
 * Returns both possible y values or null if x is not on the curve
 */
export function recoverY(x: bigint): [bigint, bigint] | null {
  const p = P256.p;
  const rhs = mod(x * x * x + P256.a * x + P256.b, p);

  // Square root via p ≡ 3 (mod 4): sqrt = rhs^((p+1)/4) mod p
  const exp = (p + 1n) >> 2n;
  const y = modPow(rhs, exp, p);

  // Verify
  if (mod(y * y, p) !== rhs) {
    return null;
  }

  return [y, mod(p - y, p)];
}

// ─── Demo Backdoor ──────────────────────────────────────────────────

/**
 * For the demo, we choose a known scalar e and compute Q = e·P.
 * This proves the attack mechanism works.
 *
 * We are NOT claiming to know the actual NSA backdoor scalar for NIST's Q.
 * This is a demonstration of why the mathematical structure is dangerous.
 */
export const DEMO_BACKDOOR_E = BigInt(
  '0xdeadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef'
);

/** Our demo Q where we know e such that Q = e·G */
export const DEMO_Q: ECPoint = scalarMult(DEMO_BACKDOOR_E, NIST_P);

/** d = e^(-1) mod n — used in state recovery */
export const DEMO_BACKDOOR_D: bigint = modPow(DEMO_BACKDOOR_E, P256.n - 2n, P256.n);

// ─── Dual_EC_DRBG State Machine ─────────────────────────────────────

/**
 * Convert a bigint to a big-endian Uint8Array of specified length
 */
export function bigintToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a bigint (big-endian)
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Dual_EC_DRBG Generate (per SP 800-90A §10.3.1)
 *
 * Given state s:
 *   1. s_new = (s · P).x   — state update via P
 *   2. r     = (s_new · Q).x — output derived via Q
 *   3. output = truncate(r) — drop high 16 bits → 30 bytes of output
 *   4. carry s_new forward
 *
 * The backdoor: output reveals 240 of 256 bits of r = (s_new · Q).x.
 * Anyone who knows d = e⁻¹ mod n (where Q = e·P) can compute
 * d · R = d · (s_new · Q) = s_new · P, recovering (s_new · P).x — the
 * NEXT state update value — from a single output block.
 *
 * @param s - Current internal state (scalar)
 * @param P - The P point (generator, used for state update)
 * @param Q - The Q point (potentially backdoored, used for output)
 */
export function dualEcGenerate(
  s: bigint,
  P: ECPoint = NIST_P,
  Q: ECPoint = DEMO_Q
): {
  output: Uint8Array;
  nextState: bigint;
  rPoint: ECPoint;
} {
  // Step 1: s_new = (s · P).x  — state update
  const sP = scalarMult(s, P);
  const sNew = sP.x;

  // Step 2: r = (s_new · Q).x  — output computation
  const sQ = scalarMult(sNew, Q);
  const r = sQ.x;

  // Step 3: output = truncate(r)
  // For P-256, x-coordinate is 32 bytes. Drop high 16 bits (2 bytes) → 30 bytes
  const rBytes = bigintToBytes(r, 32);
  const output = rBytes.slice(2); // drop first 2 bytes (high 16 bits)

  return {
    output,
    nextState: sNew,  // carry the P-derived state forward
    rPoint: sQ,       // the Q-derived point (output leaks most of r)
  };
}

// ─── DRBG Interface ─────────────────────────────────────────────────

import type { DRBGState, GenerateResult } from '../types/drbg';

/**
 * Instantiate Dual_EC_DRBG
 * Initial state s₀ is derived from entropy input
 */
export async function dualEcDrbgInstantiate(
  entropyInput: Uint8Array,
  _nonce: Uint8Array,
  _personalization: Uint8Array,
  securityStrength: 128 | 192 | 256
): Promise<DRBGState> {
  // Hash entropy to get initial state scalar
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', entropyInput.buffer.slice(entropyInput.byteOffset, entropyInput.byteOffset + entropyInput.byteLength) as ArrayBuffer)
  );
  const s0 = mod(bytesToBigint(hash), P256.n - 1n) + 1n;

  return {
    algorithm: 'Dual-EC-DRBG',
    instantiated: true,
    reseedCounter: 1,
    securityStrength,
    internalState: bigintToBytes(s0, 32),
  };
}

/**
 * Reseed Dual_EC_DRBG
 */
export async function dualEcDrbgReseed(
  state: DRBGState,
  entropyInput: Uint8Array,
  _additionalInput: Uint8Array
): Promise<DRBGState> {
  const oldS = bytesToBigint(state.internalState);
  const entropyHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', entropyInput.buffer.slice(entropyInput.byteOffset, entropyInput.byteOffset + entropyInput.byteLength) as ArrayBuffer)
  );
  const entropyScalar = bytesToBigint(entropyHash);
  const newS = mod(oldS + entropyScalar, P256.n - 1n) + 1n;

  return {
    ...state,
    reseedCounter: 1,
    internalState: bigintToBytes(newS, 32),
  };
}

/**
 * Generate from Dual_EC_DRBG
 *
 * Each call produces 30 bytes of output (one EC operation pair).
 * For more bytes, multiple rounds are chained.
 */
export async function dualEcDrbgGenerate(
  state: DRBGState,
  requestedBits: number,
  _additionalInput: Uint8Array,
  P: ECPoint = NIST_P,
  Q: ECPoint = DEMO_Q
): Promise<{ state: DRBGState; result: GenerateResult; rounds: Array<{ output: Uint8Array; rPoint: ECPoint }> }> {
  const requestedBytes = Math.ceil(requestedBits / 8);
  const bytesPerRound = 30;
  const roundsNeeded = Math.ceil(requestedBytes / bytesPerRound);

  let s = bytesToBigint(state.internalState);
  const allOutput: Uint8Array[] = [];
  const rounds: Array<{ output: Uint8Array; rPoint: ECPoint }> = [];

  for (let i = 0; i < roundsNeeded; i++) {
    const result = dualEcGenerate(s, P, Q);
    allOutput.push(result.output);
    rounds.push({ output: result.output, rPoint: result.rPoint });
    s = result.nextState;
  }

  // Concatenate and trim
  const fullOutput = new Uint8Array(roundsNeeded * bytesPerRound);
  let offset = 0;
  for (const chunk of allOutput) {
    fullOutput.set(chunk, offset);
    offset += chunk.length;
  }

  const newState: DRBGState = {
    ...state,
    reseedCounter: state.reseedCounter + 1,
    internalState: bigintToBytes(s, 32),
  };

  return {
    state: newState,
    result: {
      bytes: fullOutput.slice(0, requestedBytes),
      reseedRequired: false,
      reseedCounter: newState.reseedCounter,
    },
    rounds,
  };
}
