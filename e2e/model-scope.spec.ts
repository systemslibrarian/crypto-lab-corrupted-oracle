import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`Dual_EC model limits are visible before controls and in ABOUT at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await page.goto('.');
    const notice = page.getByRole('note', { name: 'Dual_EC model limits' });
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('not the complete NIST DRBG');
    await expect(notice).toContainText('extra P update');
    await expect(notice).toContainText('counts requests');
    await expect(notice).toContainText('ignores nonce, personalization and additional input');
    await expect(notice).toContainText('no reseed interval');
    await expect(notice).toContainText('P-256');
    const precedes = await page.locator('.three-panel').evaluate(el => {
      const n = document.getElementById('dual-ec-model-scope');
      return !!n && !!(n.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);
    });
    expect(precedes).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    // Wait for real wiring, not just initially enabled buttons during entropy collection.
    await expect.poll(async () => {
      await page.locator('.three-panel > .panel').first().getByRole('button', { name: /^Generate/ }).click();
      return await page.locator('.three-panel > .panel').first().locator('.hex-output').textContent();
    }).toMatch(/^[0-9a-f]{64}$/);
    await expect(page.locator('#stats-output')).toContainText('Generate output from all three algorithms');
    await page.locator('#btn-about').click();
    const about = page.getByRole('dialog');
    await expect(about).toContainText('Simplified request lifecycle');
    await expect(about).toContainText('step 14');
    await expect(about).toContainText('step 10');
    await expect(about).toContainText('SHA-256');
    await expect(about).toContainText('not a claim of 256-bit security');
    await expect(about.locator('a[href="https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-90a.pdf#page=76"]')).toHaveCount(1);
    await about.getByRole('button', { name: /close/i }).click();
    await expect(notice).toBeVisible();
  });
}
