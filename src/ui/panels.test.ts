// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from 'vitest';
import { initUI } from './panels';

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
