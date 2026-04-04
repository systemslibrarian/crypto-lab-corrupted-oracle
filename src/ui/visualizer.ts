/**
 * Bit Heatmap Visualizer
 *
 * Renders a 16×16 grid of generated bits per algorithm.
 * 0-bits are dark, 1-bits are accent-colored.
 * Shows visually that all three algorithms look identical —
 * the Dual_EC backdoor is invisible to visual inspection.
 */

/** Render a 16×16 bit heatmap into a container element */
export function renderBitHeatmap(
  container: HTMLElement,
  bytes: Uint8Array,
  variant: 'clean' | 'corrupt'
): void {
  container.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'bit-grid';
  grid.setAttribute('role', 'img');
  grid.setAttribute('aria-label', `Bit pattern visualization: ${variant === 'clean' ? 'clean algorithm' : 'compromised algorithm'}`);

  // We need 256 bits = 32 bytes for a 16×16 grid
  const needed = 32;
  const src = bytes.length >= needed ? bytes : padBytes(bytes, needed);

  for (let byteIdx = 0; byteIdx < needed; byteIdx++) {
    for (let bit = 7; bit >= 0; bit--) {
      const cell = document.createElement('div');
      const bitVal = (src[byteIdx] >> bit) & 1;
      if (bitVal === 0) {
        cell.className = 'bit-cell bit-0';
      } else {
        cell.className = `bit-cell bit-1-${variant}`;
      }
      grid.appendChild(cell);
    }
  }

  container.appendChild(grid);
}

function padBytes(bytes: Uint8Array, targetLen: number): Uint8Array {
  const result = new Uint8Array(targetLen);
  result.set(bytes.subarray(0, Math.min(bytes.length, targetLen)));
  return result;
}
