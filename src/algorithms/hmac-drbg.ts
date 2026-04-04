/**
 * HMAC-DRBG Implementation
 * Per NIST SP 800-90A Rev 1, Section 10.1.2
 * Using HMAC-SHA-256 as the underlying HMAC function.
 *
 * WebCrypto is used ONLY for the HMAC-SHA-256 primitive itself.
 */

import type { DRBGState, GenerateResult, HMACDRBGInternalState } from '../types/drbg';

/** Maximum number of generate requests before reseed required (Table 2, §10.1.2) */
const RESEED_INTERVAL = 10_000;

/** HMAC-SHA-256 outlen in bytes */
const OUTLEN = 32;

/** Compute HMAC-SHA-256 using WebCrypto */
async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC', cryptoKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
  );
  return new Uint8Array(sig);
}

/** Concatenate Uint8Arrays */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * §10.1.2.2 — HMAC_DRBG_Update
 *
 * Updates the internal state (K, V) using provided_data.
 * Steps:
 *   1. K = HMAC(K, V || 0x00 || provided_data)
 *   2. V = HMAC(K, V)
 *   3. If provided_data is null or empty, return (K, V)
 *   4. K = HMAC(K, V || 0x01 || provided_data)
 *   5. V = HMAC(K, V)
 *   6. Return (K, V)
 */
async function hmacDrbgUpdate(
  providedData: Uint8Array | null,
  K: Uint8Array,
  V: Uint8Array
): Promise<{ K: Uint8Array; V: Uint8Array }> {
  // Step 1
  const separator0 = new Uint8Array([0x00]);
  const concatData0 = providedData !== null && providedData.length > 0
    ? concat(V, separator0, providedData)
    : concat(V, separator0);
  K = await hmac(K, concatData0);

  // Step 2
  V = await hmac(K, V);

  // Step 3
  if (providedData === null || providedData.length === 0) {
    return { K, V };
  }

  // Step 4
  const separator1 = new Uint8Array([0x01]);
  K = await hmac(K, concat(V, separator1, providedData));

  // Step 5
  V = await hmac(K, V);

  // Step 6
  return { K, V };
}

/** Serialize HMAC-DRBG internal state (K||V) into a single buffer */
function serializeState(K: Uint8Array, V: Uint8Array): Uint8Array {
  return concat(K, V);
}

/** Deserialize HMAC-DRBG internal state from single buffer */
function deserializeState(buf: Uint8Array): HMACDRBGInternalState {
  return {
    K: buf.slice(0, OUTLEN),
    V: buf.slice(OUTLEN, OUTLEN * 2),
  };
}

/**
 * §10.1.2.3 — HMAC_DRBG_Instantiate_algorithm
 *
 * Process:
 *   1. seed_material = entropy_input || nonce || personalization_string
 *   2. K = 0x00 00...00 (outlen bytes)
 *   3. V = 0x01 01...01 (outlen bytes)
 *   4. (K, V) = HMAC_DRBG_Update(seed_material, K, V)
 *   5. reseed_counter = 1
 *   6. Return state
 */
export async function hmacDrbgInstantiate(
  entropyInput: Uint8Array,
  nonce: Uint8Array,
  personalizationString: Uint8Array,
  securityStrength: 128 | 192 | 256
): Promise<DRBGState> {
  // Step 1
  const seedMaterial = concat(entropyInput, nonce, personalizationString);

  // Steps 2-3
  let kv = await hmacDrbgUpdate(
    seedMaterial,
    new Uint8Array(OUTLEN),
    new Uint8Array(OUTLEN).fill(0x01)
  );
  let K = kv.K;
  let V = kv.V;

  // Steps 5-6
  return {
    algorithm: 'HMAC-DRBG',
    instantiated: true,
    reseedCounter: 1,
    securityStrength,
    internalState: serializeState(K, V),
  };
}

/**
 * §10.1.2.4 — HMAC_DRBG_Reseed_algorithm
 *
 * Process:
 *   1. seed_material = entropy_input || additional_input
 *   2. (K, V) = HMAC_DRBG_Update(seed_material, K, V)
 *   3. reseed_counter = 1
 *   4. Return state
 */
export async function hmacDrbgReseed(
  state: DRBGState,
  entropyInput: Uint8Array,
  additionalInput: Uint8Array
): Promise<DRBGState> {
  let { K, V } = deserializeState(state.internalState);

  // Step 1
  const seedMaterial = concat(entropyInput, additionalInput);

  // Step 2
  ({ K, V } = await hmacDrbgUpdate(seedMaterial, K, V));

  // Step 3
  return {
    ...state,
    reseedCounter: 1,
    internalState: serializeState(K, V),
  };
}

/**
 * §10.1.2.5 — HMAC_DRBG_Generate_algorithm
 *
 * Process:
 *   1. If reseed_counter > reseed_interval, return indication that reseed is required
 *   2. If additional_input is not empty:
 *      (K, V) = HMAC_DRBG_Update(additional_input, K, V)
 *   3. temp = empty
 *   4. While len(temp) < requested_number_of_bits:
 *      V = HMAC(K, V)
 *      temp = temp || V
 *   5. returned_bits = leftmost(temp, requested_number_of_bits)
 *   6. (K, V) = HMAC_DRBG_Update(additional_input, K, V)
 *   7. reseed_counter = reseed_counter + 1
 *   8. Return (returned_bits, state)
 */
export async function hmacDrbgGenerate(
  state: DRBGState,
  requestedBits: number,
  additionalInput: Uint8Array
): Promise<{ state: DRBGState; result: GenerateResult }> {
  // Step 1
  if (state.reseedCounter > RESEED_INTERVAL) {
    return {
      state,
      result: {
        bytes: new Uint8Array(0),
        reseedRequired: true,
        reseedCounter: state.reseedCounter,
      },
    };
  }

  let { K, V } = deserializeState(state.internalState);

  // Step 2
  if (additionalInput.length > 0) {
    ({ K, V } = await hmacDrbgUpdate(additionalInput, K, V));
  }

  // Steps 3-4
  const requestedBytes = Math.ceil(requestedBits / 8);
  const temp: Uint8Array[] = [];
  let generated = 0;
  while (generated < requestedBytes) {
    V = await hmac(K, V);
    temp.push(V);
    generated += V.length;
  }

  // Step 5
  const fullOutput = concat(...temp);
  const returnedBits = fullOutput.slice(0, requestedBytes);

  // Step 6
  ({ K, V } = await hmacDrbgUpdate(additionalInput, K, V));

  // Step 7
  const newReseedCounter = state.reseedCounter + 1;

  // Step 8
  const newState: DRBGState = {
    ...state,
    reseedCounter: newReseedCounter,
    internalState: serializeState(K, V),
  };

  return {
    state: newState,
    result: {
      bytes: returnedBits,
      reseedRequired: false,
      reseedCounter: newReseedCounter,
    },
  };
}
