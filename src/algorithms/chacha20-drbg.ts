/**
 * ChaCha20-DRBG Implementation
 *
 * Based on the ChaCha20 stream cipher as specified in RFC 8439 §2.1.
 * This DRBG construction follows the same principles used in OpenBSD's
 * arc4random (ChaCha20-based) and the Linux kernel's getrandom().
 *
 * The ChaCha20 keystream is used as DRBG output. Reseeding replaces
 * the key with fresh entropy XORed with accumulated state.
 */

import type { DRBGState, GenerateResult } from '../types/drbg';

/** ChaCha20 block size in bytes */
const BLOCK_SIZE = 64;

/** Maximum blocks before mandatory reseed (conservative) */
const MAX_BLOCKS_BEFORE_RESEED = 65536;

/**
 * Quarter-round function per RFC 8439 §2.1
 * QR(a, b, c, d):
 *   a += b; d ^= a; d <<<= 16;
 *   c += d; b ^= c; b <<<= 12;
 *   a += b; d ^= a; d <<<= 8;
 *   c += d; b ^= c; b <<<= 7;
 */
function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = (state[d] ^ state[a]) >>> 0;
  state[d] = ((state[d] << 16) | (state[d] >>> 16)) >>> 0;

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = (state[b] ^ state[c]) >>> 0;
  state[b] = ((state[b] << 12) | (state[b] >>> 20)) >>> 0;

  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = (state[d] ^ state[a]) >>> 0;
  state[d] = ((state[d] << 8) | (state[d] >>> 24)) >>> 0;

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = (state[b] ^ state[c]) >>> 0;
  state[b] = ((state[b] << 7) | (state[b] >>> 25)) >>> 0;
}

/**
 * ChaCha20 block function per RFC 8439 §2.3
 *
 * State layout (16 x 32-bit words):
 *   [0..3]   = "expand 32-byte k" constants
 *   [4..11]  = 256-bit key
 *   [12]     = block counter
 *   [13..15] = 96-bit nonce
 *
 * 20 rounds = 10 iterations of (4 column rounds + 4 diagonal rounds)
 * Final state = initial state + working state (word-wise addition)
 */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('ChaCha20 key must be 32 bytes');
  if (nonce.length !== 12) throw new Error('ChaCha20 nonce must be 12 bytes');

  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);

  // Initial state
  const state = new Uint32Array(16);
  // Constants: "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // Key (little-endian)
  for (let i = 0; i < 8; i++) {
    state[4 + i] = keyView.getUint32(i * 4, true);
  }

  // Counter
  state[12] = counter >>> 0;

  // Nonce (little-endian)
  for (let i = 0; i < 3; i++) {
    state[13 + i] = nonceView.getUint32(i * 4, true);
  }

  // Working copy
  const working = new Uint32Array(state);

  // 20 rounds (10 double-rounds)
  for (let i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    // Diagonal rounds
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  // Add initial state to working state
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i] + state[i]) >>> 0;
  }

  // Serialize to little-endian bytes
  const output = new Uint8Array(BLOCK_SIZE);
  const outView = new DataView(output.buffer);
  for (let i = 0; i < 16; i++) {
    outView.setUint32(i * 4, working[i], true);
  }
  return output;
}

/** Serialize ChaCha20 DRBG state: key (32) || nonce (12) || counter (8) */
function serializeState(key: Uint8Array, nonce: Uint8Array, counter: bigint): Uint8Array {
  const buf = new Uint8Array(52);
  buf.set(key, 0);
  buf.set(nonce, 32);
  const view = new DataView(buf.buffer);
  view.setBigUint64(44, counter, true);
  return buf;
}

/** Deserialize ChaCha20 DRBG state */
function deserializeState(buf: Uint8Array): { key: Uint8Array; nonce: Uint8Array; counter: bigint } {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    key: buf.slice(0, 32),
    nonce: buf.slice(32, 44),
    counter: view.getBigUint64(44, true),
  };
}

/**
 * Instantiate ChaCha20-DRBG
 *
 * Seeds the DRBG with entropy. Key = first 32 bytes of entropy,
 * nonce = bytes 32..44, counter starts at 0.
 */
export async function chacha20DrbgInstantiate(
  entropyInput: Uint8Array,
  _nonce: Uint8Array,
  _personalization: Uint8Array,
  securityStrength: 128 | 192 | 256
): Promise<DRBGState> {
  // Hash entropy to get uniform seed material
  const seed = new Uint8Array(
    await crypto.subtle.digest('SHA-256', entropyInput.buffer.slice(entropyInput.byteOffset, entropyInput.byteOffset + entropyInput.byteLength) as ArrayBuffer)
  );

  const key = seed.slice(0, 32);
  // Generate nonce from additional entropy
  const nonceSource = new Uint8Array(
    await crypto.subtle.digest('SHA-256', _nonce.buffer.slice(_nonce.byteOffset, _nonce.byteOffset + _nonce.byteLength) as ArrayBuffer)
  );
  const nonce = nonceSource.slice(0, 12);

  return {
    algorithm: 'ChaCha20-DRBG',
    instantiated: true,
    reseedCounter: 1,
    securityStrength,
    internalState: serializeState(key, nonce, 0n),
  };
}

/**
 * Reseed ChaCha20-DRBG
 *
 * XOR new entropy with existing key, hash the result to produce new key.
 * Reset counter.
 */
export async function chacha20DrbgReseed(
  state: DRBGState,
  entropyInput: Uint8Array,
  _additionalInput: Uint8Array
): Promise<DRBGState> {
  const { key: oldKey } = deserializeState(state.internalState);

  // XOR entropy with old key then hash
  const mixed = new Uint8Array(Math.max(oldKey.length, entropyInput.length));
  for (let i = 0; i < mixed.length; i++) {
    mixed[i] = (oldKey[i % oldKey.length] ?? 0) ^ (entropyInput[i % entropyInput.length] ?? 0);
  }
  const newKey = new Uint8Array(await crypto.subtle.digest('SHA-256', mixed.buffer.slice(mixed.byteOffset, mixed.byteOffset + mixed.byteLength) as ArrayBuffer));
  const nonceBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', entropyInput.buffer.slice(entropyInput.byteOffset, entropyInput.byteOffset + entropyInput.byteLength) as ArrayBuffer)
  );

  return {
    ...state,
    reseedCounter: 1,
    internalState: serializeState(newKey, nonceBytes.slice(0, 12), 0n),
  };
}

/**
 * Generate random bytes from ChaCha20-DRBG
 *
 * Uses the ChaCha20 keystream directly as DRBG output.
 */
export async function chacha20DrbgGenerate(
  state: DRBGState,
  requestedBits: number,
  _additionalInput: Uint8Array
): Promise<{ state: DRBGState; result: GenerateResult }> {
  const requestedBytes = Math.ceil(requestedBits / 8);
  const { key, nonce, counter } = deserializeState(state.internalState);

  const blocksNeeded = Math.ceil(requestedBytes / BLOCK_SIZE);

  // Check reseed requirement
  if (Number(counter) + blocksNeeded > MAX_BLOCKS_BEFORE_RESEED) {
    return {
      state,
      result: {
        bytes: new Uint8Array(0),
        reseedRequired: true,
        reseedCounter: state.reseedCounter,
      },
    };
  }

  const output = new Uint8Array(blocksNeeded * BLOCK_SIZE);
  let currentCounter = counter;
  for (let i = 0; i < blocksNeeded; i++) {
    const block = chacha20Block(key, Number(currentCounter) & 0xFFFFFFFF, nonce);
    output.set(block, i * BLOCK_SIZE);
    currentCounter++;
  }

  const newState: DRBGState = {
    ...state,
    reseedCounter: state.reseedCounter + 1,
    internalState: serializeState(key, nonce, currentCounter),
  };

  return {
    state: newState,
    result: {
      bytes: output.slice(0, requestedBytes),
      reseedRequired: false,
      reseedCounter: newState.reseedCounter,
    },
  };
}
