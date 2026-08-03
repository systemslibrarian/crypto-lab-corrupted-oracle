// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from 'vitest';
import { formatPValue, initUI } from './panels';

function tick(ms = 0): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function buttonByText(text: string): HTMLButtonElement | undefined {
  return Array.from(document.querySelectorAll('button')).find(
    (b) => b.textContent?.trim() === text,
  ) as HTMLButtonElement | undefined;
}

describe('UI wiring (smoke test, no attack)', () => {
  beforeEach(() => {
    document.body.innerHTML =
      '<div id="app"></div>' +
      '<div id="sr-announcer" aria-live="assertive"></div>';
  });

  it('renders the three algorithm panels and the controls', async () => {
    await initUI();
    expect(document.querySelectorAll('.panel').length).toBeGreaterThanOrEqual(3);
    expect(document.body.textContent).toContain('HMAC-DRBG');
    expect(document.body.textContent).toContain('ChaCha20-DRBG');
    expect(document.body.textContent).toContain('Dual_EC_DRBG');
    expect(buttonByText('TRIGGER ATTACK')).toBeDefined();
  });

  it('Generate produces hex output', async () => {
    await initUI();
    const gen = buttonByText('Generate');
    expect(gen).toBeDefined();
    gen!.click();
    await tick(20);
    const outputs = Array.from(document.querySelectorAll('.hex-output'))
      .map((el) => el.textContent ?? '');
    expect(outputs.some((t) => /[0-9a-f]{32}/.test(t))).toBe(true);
  });

  it('About modal verifies the trapdoor (d·Q = P) live', async () => {
    await initUI();
    buttonByText('ABOUT')!.click();
    await tick(20);
    const text = document.body.textContent ?? '';
    expect(text).toContain('trapdoor verified live');
    // The check must PASS (✓), never fail (✗).
    expect(text).toContain('✓ trapdoor verified live');
  });
});

describe('p-value rendering', () => {
  it('never prints a number on the wrong side of its own verdict', () => {
    // Regression: the table used to render a passing p of 0.0104 with
    // toFixed(3), producing "✅ p=0.010" — a pass badge beside a number that,
    // as printed, is not above the 0.01 threshold the badge was decided by.
    // A browser run caught this live at "✅ p=0.010".
    expect(formatPValue(0.0104, true)).toBe('0.0104');

    for (const p of [0.010001, 0.01004, 0.0105, 0.0100004, 0.011, 0.02, 0.5, 1]) {
      const shown = formatPValue(p, true);
      expect(Number(shown), `p=${p} rendered as ${shown}`).toBeGreaterThan(0.01);
    }
    for (const p of [0.001, 0.005, 0.0099, 0.00999, 0.01]) {
      const shown = formatPValue(p, false);
      expect(Number(shown), `p=${p} rendered as ${shown}`).toBeLessThanOrEqual(0.01);
    }

    // Below a thousandth the exact value stops carrying information.
    expect(formatPValue(0.0004, false)).toBe('<0.001');
    expect(formatPValue(0, false)).toBe('<0.001');

    // If no precision can separate the value from the threshold, name the side
    // rather than print a number that contradicts the verdict.
    expect(formatPValue(0.01 + 1e-12, true)).toBe('>0.01');
  });
});
