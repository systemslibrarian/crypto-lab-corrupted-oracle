// @vitest-environment happy-dom
import { describe, it, expect } from 'vitest';
import { renderBitHeatmap } from './visualizer';

function grid(bytes: Uint8Array, label = 'test'): HTMLElement {
  const container = document.createElement('div');
  renderBitHeatmap(container, bytes, label);
  return container.querySelector('.bit-grid') as HTMLElement;
}

describe('bit heatmap', () => {
  it('paints lit bits the same colour class whatever the source', () => {
    // The page's thesis is that the three streams are indistinguishable. The
    // grid used to take a 'clean' | 'corrupt' variant from the calling panel
    // and tint the Dual_EC one red, which drew a difference the data does not
    // contain. Identical bytes must now produce identical markup.
    const bytes = new Uint8Array(32).fill(0b10110010);
    const honest = grid(bytes, 'HMAC-DRBG').innerHTML;
    const backdoored = grid(bytes, 'Dual_EC_DRBG').innerHTML;
    expect(backdoored).toBe(honest);
    expect(honest).toContain('bit-1');
    expect(honest).not.toContain('bit-1-corrupt');
  });

  it('sizes the grid to the data instead of zero-padding it', () => {
    // Dual_EC emits 240 bits = 30 bytes. A fixed 16x16 grid padded that to 32
    // bytes, so the panel carried a permanent all-dark bottom row that came
    // from the padding rather than from the generator.
    const thirtyBytes = new Uint8Array(30).fill(0xff);
    const cells = grid(thirtyBytes).querySelectorAll('.bit-cell');
    expect(cells.length).toBe(240);
    // Every bit is a 1, so no cell may be dark.
    expect(grid(thirtyBytes).querySelectorAll('.bit-cell.bit-0').length).toBe(0);
  });

  it('drops a trailing partial row rather than padding it', () => {
    // 17 bytes = 136 bits: one full 16-bit row would be left half-empty.
    const cells = grid(new Uint8Array(17).fill(0xff)).querySelectorAll('.bit-cell');
    expect(cells.length % 16).toBe(0);
    expect(cells.length).toBe(128);
  });

  it('reports the measured 1-bit count in its accessible label', () => {
    const bytes = new Uint8Array(32);
    bytes[0] = 0xff; // exactly 8 ones
    const label = grid(bytes, 'HMAC-DRBG').getAttribute('aria-label') ?? '';
    expect(label).toContain('HMAC-DRBG');
    expect(label).toContain('256 bits, 8 of them 1');
  });
});
