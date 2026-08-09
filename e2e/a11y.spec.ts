import { test } from '@playwright/test';
import { boot, driveAllStates, reportCollected, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: Generate pressed on all three
 * generators so both hex tones and all three bit heatmaps exist, HMAC reseeded,
 * the SP 800-22 statistics run so the "they all pass" table is real, the
 * backdoor attack triggered end to end through its intercepted blocks, progress
 * bar, recovered state, ten prediction rows and summary, the armed prediction
 * confirmed by a further Generate, then defeated by a Reseed and shown stale by
 * the Generate after it, and both dialogs opened and closed by their own Close
 * buttons. Every resulting state is scanned in both themes at desktop and phone
 * width — four configurations, because a gate that scans one scans one half,
 * and which half depends on the lab's defaults.
 *
 * See `gate.ts` for why nothing is injected into the page (and why the injected
 * `width: auto !important` was the test fabricating the layout it measured),
 * why reduced motion is asked for rather than forced, why the defaults are
 * asserted rather than assumed, why no region is force-revealed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
  });
}
