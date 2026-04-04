/**
 * Browser Entropy Harvester
 *
 * Collects entropy from multiple browser sources, mixes them via SHA-256.
 *
 * Entropy sources and their actual contributions:
 * 1. crypto.getRandomValues() — Primary source. Full entropy. This is backed by
 *    the OS CSPRNG (e.g., /dev/urandom, CryptGenRandom). Honest: this alone
 *    would suffice; the other sources are supplemental.
 * 2. performance.now() timing jitter — Sub-microsecond timing noise across
 *    async yields. Real entropy contribution: ~1-4 bits per sample due to
 *    timer resolution limits and quantization. We collect 16 samples.
 * 3. Mouse/touch movement deltas — If available, last 32 events' x/y deltas.
 *    Real entropy contribution: variable, ~2-6 bits per event when user is
 *    actively moving mouse. Zero if no movement has occurred.
 * 4. Date.now() — Millisecond timestamp. Very weak source (~0-1 bits of real
 *    entropy per call). Included for completeness, not relied upon.
 *
 * Mix: All sources concatenated then hashed with SHA-256.
 */

// Accumulated movement events
const movementBuffer: Array<{ dx: number; dy: number; t: number }> = [];
const MAX_MOVEMENT_EVENTS = 32;

/** Start collecting mouse/touch movement entropy */
export function startMovementCollection(): void {
  if (typeof window === 'undefined') return;

  const handler = (e: MouseEvent | TouchEvent) => {
    let dx = 0, dy = 0;
    if (e instanceof MouseEvent) {
      dx = e.movementX;
      dy = e.movementY;
    } else if (e instanceof TouchEvent && e.touches.length > 0) {
      dx = e.touches[0].clientX;
      dy = e.touches[0].clientY;
    }
    movementBuffer.push({ dx, dy, t: performance.now() });
    if (movementBuffer.length > MAX_MOVEMENT_EVENTS) {
      movementBuffer.shift();
    }
  };

  window.addEventListener('mousemove', handler, { passive: true });
  window.addEventListener('touchmove', handler, { passive: true });
}

/**
 * Harvest entropy from all available browser sources
 *
 * @param bytes - Number of bytes of entropy to produce
 * @returns Uint8Array of mixed entropy
 */
export async function harvestEntropy(bytes: number): Promise<Uint8Array> {
  const sources: Uint8Array[] = [];

  // Source 1: crypto.getRandomValues() — full entropy
  const csprng = new Uint8Array(bytes);
  crypto.getRandomValues(csprng);
  sources.push(csprng);

  // Source 2: performance.now() timing jitter
  const timingData = new Float64Array(16);
  for (let i = 0; i < 16; i++) {
    await new Promise(resolve => setTimeout(resolve, 0)); // async yield
    timingData[i] = performance.now();
  }
  sources.push(new Uint8Array(timingData.buffer));

  // Source 3: Mouse/touch movement accumulation
  if (movementBuffer.length > 0) {
    const movementData = new Float64Array(movementBuffer.length * 3);
    for (let i = 0; i < movementBuffer.length; i++) {
      movementData[i * 3] = movementBuffer[i].dx;
      movementData[i * 3 + 1] = movementBuffer[i].dy;
      movementData[i * 3 + 2] = movementBuffer[i].t;
    }
    sources.push(new Uint8Array(movementData.buffer));
  }

  // Source 4: Date.now() — weak
  const dateBytes = new Uint8Array(8);
  const dateView = new DataView(dateBytes.buffer);
  dateView.setFloat64(0, Date.now());
  sources.push(dateBytes);

  // Mix: concatenate all sources and hash with SHA-256
  // Repeat hashing to produce requested number of bytes
  const totalLen = sources.reduce((s, a) => s + a.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const src of sources) {
    combined.set(src, offset);
    offset += src.length;
  }

  const result = new Uint8Array(bytes);
  let produced = 0;
  let counter = 0;

  while (produced < bytes) {
    // Append counter to combined for domain separation
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);
    const input = new Uint8Array(combined.length + 4);
    input.set(combined);
    input.set(counterBytes, combined.length);

    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    const toCopy = Math.min(hash.length, bytes - produced);
    result.set(hash.subarray(0, toCopy), produced);
    produced += toCopy;
    counter++;
  }

  return result;
}
