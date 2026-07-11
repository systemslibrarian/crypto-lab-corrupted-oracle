import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way.
 *
 * This lab has no <details>. Instead it has class-toggled / display-toggled
 * regions: the attack theater (display:none until triggered) and two modal
 * dialogs (KAT + ABOUT) that are appended to <body> on button click. A modal's
 * full-screen backdrop covers the page, so only one can be open at a time —
 * we scan the base page (with the attack theater revealed) and then each modal
 * individually. Animations/transitions are neutralized so nothing is scanned
 * mid-transition.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; }\n' +
      'body { animation: none !important; }\n' +
      '.typewriter-text { animation: none !important; width: auto !important; }',
  });
}

async function revealInline(page: Page): Promise<void> {
  // Expand any native <details> (none today, but future-proof) and reveal any
  // display:none inline regions such as the attack theater.
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>('*')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function scanModal(page: Page, triggerId: string): Promise<void> {
  await page.locator(`#${triggerId}`).click();
  const backdrop = page.locator('.modal-backdrop');
  await expect(backdrop).toBeVisible();
  await neutralizeMotion(page);
  await scan(page);
  // Close so the next modal (or a clean page) is unobstructed.
  await backdrop.getByRole('button', { name: /close/i }).click();
  await expect(page.locator('.modal-backdrop')).toHaveCount(0);
}

async function runSuite(page: Page): Promise<void> {
  await revealInline(page);
  await neutralizeMotion(page);
  await scan(page);
  await scanModal(page, 'btn-kat');
  await scanModal(page, 'btn-about');
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
