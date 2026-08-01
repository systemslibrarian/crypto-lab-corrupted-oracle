/**
 * Bit Heatmap Visualizer
 *
 * Renders the bits of a generated block as a 16-column grid.
 * 0-bits are dark, 1-bits are lit.
 *
 * Two deliberate properties, both of which the page's thesis depends on:
 *
 *  1. The lit colour is the SAME for all three generators. It used to be chosen
 *     by which panel was calling — green for the honest two, red for Dual_EC —
 *     which painted a visible difference onto three streams the whole page
 *     exists to argue are indistinguishable. The colour is now a property of
 *     the grid, not of the caller's opinion of the algorithm.
 *  2. The grid is sized to the data. It used to be a fixed 16x16 = 32 bytes,
 *     while the Dual_EC panel supplies 240 bits = 30 bytes; the missing two
 *     bytes were zero-padded, so that grid carried a permanent all-dark bottom
 *     row that was an artifact of padding, not of the generator. Rows are now
 *     floor(bits / 16) and nothing is padded.
 */

/** Bits per grid row — must match `.bit-grid { grid-template-columns }`. */
const COLUMNS = 16;

/**
 * Render a bit heatmap into a container element.
 *
 * `label` names the source for assistive technology only; it does not change
 * a single rendered pixel.
 */
export function renderBitHeatmap(
  container: HTMLElement,
  bytes: Uint8Array,
  label: string,
): void {
  container.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'bit-grid';
  grid.setAttribute('role', 'img');

  // Whole rows only: a partial row would be indistinguishable from padding,
  // which is the defect this replaces.
  const usableBytes = Math.floor((bytes.length * 8) / COLUMNS) * (COLUMNS / 8);
  let ones = 0;

  for (let byteIdx = 0; byteIdx < usableBytes; byteIdx++) {
    for (let bit = 7; bit >= 0; bit--) {
      const cell = document.createElement('div');
      const bitVal = ((bytes[byteIdx] ?? 0) >> bit) & 1;
      if (bitVal === 0) {
        cell.className = 'bit-cell bit-0';
      } else {
        cell.className = 'bit-cell bit-1';
        ones++;
      }
      grid.appendChild(cell);
    }
  }

  const totalBits = usableBytes * 8;
  // The label states the measured 1-bit count, so a screen-reader user gets the
  // same "these look the same" comparison a sighted user gets from the grids.
  grid.setAttribute(
    'aria-label',
    `Bit pattern from ${label}: ${totalBits} bits, ${ones} of them 1 (${
      totalBits > 0 ? ((ones / totalBits) * 100).toFixed(1) : '0.0'
    }%).`,
  );

  container.appendChild(grid);
}
