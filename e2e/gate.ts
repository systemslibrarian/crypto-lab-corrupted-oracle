import AxeBuilder from '@axe-core/playwright';
import { expect, type Locator, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each of them a correction to the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old gate pushed
 *     `animation: none !important; transition: none !important` through
 *     `addStyleTag`, plus `.typewriter-text { animation: none !important;
 *     width: auto !important }`. The first half was a near-copy of this lab's
 *     own `@media (prefers-reduced-motion: reduce)` block, so it replaced that
 *     block instead of exercising it. The `width: auto !important` was worse:
 *     `@keyframes typewriter` animated `width` from 0 to 100%, so an injected
 *     width is not a motion fix at all — it is the test fabricating the layout
 *     it then measures. Nothing in this lab ever carried `.typewriter-text`:
 *     the rule, its keyframes and its reduced-motion override were dead, which
 *     is why nobody noticed the injection was load-bearing for nothing, and all
 *     three have now been deleted. `boot` asks for the preference, asserts it
 *     took effect, injects nothing, and `settle` waits for what is running to
 *     drain — which matters here, because `body` carries
 *     `animation: crt-flicker 4s infinite` and a scan without the preference
 *     would sample the document at a random point on an opacity loop that never
 *     ends.
 *
 *  2. IT BUILT A DOCUMENT NO VISITOR CAN LOAD. `revealInline` walked EVERY
 *     element on the page and cleared any inline `display: none` it found. This
 *     lab hides a dozen regions that way — the attack container, the prediction
 *     badge, the intercepted-output block, the recovered-state line, the
 *     predictions header, the "YOUR MOVE" callout — and every one of them was
 *     forced open simultaneously, empty, in a combination the attack sequence
 *     never produces. What was scanned was a rendering that does not exist.
 *
 *  3. IT NEVER PRESSED ANYTHING. No Generate, no Reseed, no Run Tests, no
 *     Trigger Attack. Every hex output was still "—", every reseed counter
 *     still said "Not yet instantiated", the statistics table and the
 *     prediction table had never been built, and the `.hex-output.corrupted`
 *     red tone had never been painted over real bytes.
 *
 *  4. IT SCANNED TWO CONFIGURATIONS, both at desktop width. The `.stat-table`
 *     only becomes a scroller below 640px and the panels only stack there, so
 *     an entire rendering of this lab had never been looked at.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode.
 *
 * Set `A11Y_COLLECT=1` and a run records every failed assertion instead of
 * stopping at the first, so a whole configuration's findings can be read off in
 * one pass and fixed together. Unset — which is every CI run, every local run,
 * and the default in every editor — `softExpect` is an ordinary strict
 * `expect`, so this costs the gate nothing.
 *
 * The one thing that must never happen is a collecting run being mistaken for a
 * passing gate. `reportCollected`, called at the end of every test, throws if
 * anything was recorded, so a collecting run with findings still exits red and
 * still prints them.
 */
const COLLECTING = process.env.A11Y_COLLECT === '1';
const collected: string[] = [];

function softExpect(received: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(received, message).toEqual(expected);
    return;
  }
  try {
    expect(received, message).toEqual(expected);
  } catch {
    collected.push(`${message}\n  ${JSON.stringify(received, null, 2).replace(/\n/g, '\n  ')}`);
  }
}

/** Fail a collecting run that recorded anything, after printing everything. */
export function reportCollected(): void {
  if (!COLLECTING || collected.length === 0) return;
  const report = collected.join('\n\n');
  collected.length = 0;
  throw new Error(
    `A11Y_COLLECT run recorded ${report.split('\n\n').length} failing assertions:\n\n${report}`
  );
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state. This lab's
 * reduced-motion block uses `animation: none`, the cancelling form, twice — on
 * `body`'s `crt-flicker` and on `.pulse-border`. Neither is the only route to a
 * visible state: `crt-flicker` cycles opacity between 0.97 and 1, and
 * `pulse-border` cycles `border-color` between two reds on an element whose
 * `.attack-overlay` rule already sets a static one. (A third, on
 * `.typewriter-text`, cancelled a `width: 0 -> 100%` animation and WOULD have
 * been the dangerous kind; the whole rule was dead and has been deleted.) That
 * block also carries `body::after { display: none }`, which is not a motion
 * declaration at all — see `contrast.ts` on what the CRT scanline overlay costs
 * a reader who has not asked for reduced motion. This assertion is what makes
 * all of that a thing the gate rechecks rather than a thing someone once read.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`, []);
}

/** The three algorithm panels, in DOM order: HMAC, ChaCha20, Dual_EC. */
export function panel(page: Page, index: number): Locator {
  return page.locator('.three-panel > .panel').nth(index);
}
export const HMAC = 0;
export const CHACHA = 1;
export const DUAL_EC = 2;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert THE LAB'S DEFAULTS rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The default assertions below are not decoration. A gate that scans one
 * configuration scans one half, and which half depends on the defaults. Two of
 * these decide what the rest of the drive is looking at:
 *
 *  - EVERY OUTPUT IS AN EM DASH AND EVERY HEATMAP IS EMPTY. The whole page is
 *    an argument that three streams are indistinguishable, and none of the
 *    three exists until Generate is pressed. The gate this replaces never
 *    pressed it, so `.hex-output` in its green form, `.hex-output.corrupted` in
 *    its red form and 720 `.bit-cell` divs had never been scanned in any
 *    configuration.
 *  - THE ATTACK CONTAINER IS `display: none` AND HOLDS NOTHING. It is filled
 *    only by `createAttackTheater`, on click. Force-revealing it — which is
 *    exactly what the old gate did — produces an empty theater with a 0%
 *    progress bar and no prediction rows, a rendering the attack never passes
 *    through.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  // Playwright may run two of the four configurations in one worker process, so
  // a collecting run that died mid-drive could otherwise carry its findings into
  // the next test and report them against the wrong configuration.
  collected.length = 0;
  await page.emulateMedia({ reducedMotion: 'reduce' });
  // Both the anti-flash script in index.html's <head> and the shared header's
  // toggle use the key 'theme'; seeding it is the same route a returning
  // visitor takes.
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is built by `panels.ts` into an empty `#app`, so a
  // navigation that resolves proves nothing.
  await expect(page.locator('.three-panel > .panel')).toHaveCount(3);

  // `#app` must not declare a role. It used to declare `application`, which
  // switches every screen reader out of browse mode across a document made of
  // prose, headings and two data tables. Asserted here rather than trusted,
  // because it is one attribute in static markup and nothing else would notice.
  await expect(page.locator('#app')).not.toHaveAttribute('role', /.*/);
  await expect(page.locator('main#main-content')).toBeVisible();

  // ── Nothing generated ─────────────────────────────────────────────────────
  for (const i of [HMAC, CHACHA, DUAL_EC]) {
    await expect(panel(page, i).locator('.hex-output')).toHaveText('—');
    await expect(panel(page, i).locator('.bit-cell')).toHaveCount(0);
  }
  // The Dual_EC panel is the only one whose output box carries the red tone,
  // and it carries it from first paint rather than only once corrupted.
  await expect(panel(page, DUAL_EC).locator('.hex-output')).toHaveClass(/corrupted/);
  await expect(panel(page, HMAC).locator('.hex-output')).not.toHaveClass(/corrupted/);

  // ── Nothing attacked, nothing tested ──────────────────────────────────────
  await expect(page.locator('#attack-container')).toBeHidden();
  await expect(page.locator('#attack-container .prediction-row')).toHaveCount(0);
  await expect(page.locator('.stat-table')).toHaveCount(0);
  await expect(page.locator('#stats-output')).toContainText(
    'Generate output from all three algorithms'
  );
  await expect(page.locator('.modal-backdrop')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: three algorithm panels laid out by
 * `repeat(auto-fit, minmax(280px, 1fr))`, a four-column statistics table whose
 * cells are all `white-space: nowrap`, a three-column prediction table of
 * monospace hex, and 60-character intercepted-output blocks.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has the same decoy: the
    // statistics table is wider than a phone and scrolls inside its own box.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  softExpect(overflow, `page must not scroll horizontally in state: ${label}`, null);
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is the assertion that found this lab's WCAG 2.1.1 defect, and it found
 * it only because the drive runs the statistics and opens the KAT modal: below
 * 640px `.stat-table` used to become the scroller itself, four columns of
 * `white-space: nowrap` cells in a 306px box with nothing focusable in it, so
 * the Dual_EC column was unreachable from a keyboard. Both tables now sit in a
 * `.table-scroll` wrapper that is a focus target exactly while it scrolls.
 * `.hex-output` (8rem cap, 6rem on a phone) and `.modal-content` (80vh cap) are
 * the other two boxes that can scroll here; the latter holds its Close button
 * and is reachable, and the former is checked on every driven state because it
 * only overflows once something has been generated.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
    []
  );
}

/**
 * A `.table-scroll` must be a focus target exactly while it is scrolling.
 *
 * `expectScrollersReachable` above catches one half — a scroller a keyboard
 * cannot reach. This catches the other half, which is not a WCAG failure but is
 * the claim `scrollRegion` in `panels.ts` makes: a statistics table that fits
 * its panel must not leave a tab stop that does nothing. The two together turn
 * the ResizeObserver from an intention into an assertion, and they are checked
 * in all four configurations, which is the only way to see both states of a box
 * whose behaviour depends on the viewport.
 */
export async function expectTableScrollersTabbableIffScrolling(
  page: Page,
  label: string
): Promise<void> {
  const wrong = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('.table-scroll'))
      .map((el) => ({
        el,
        scrolls: el.scrollWidth > el.clientWidth + 1,
        tabbable: el.hasAttribute('tabindex'),
      }))
      .filter((x) => x.scrolls !== x.tabbable)
      .map(
        (x) =>
          `${x.el.getAttribute('aria-label') ?? '(unnamed)'} — scrolls=${x.scrolls} ` +
          `tabbable=${x.tabbable} (${x.el.scrollWidth} in ${x.el.clientWidth})`
      )
  );
  softExpect(wrong, `table scrollers must be tabbable iff scrolling in state: ${label}`, []);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every dramatic surface on the page is a translucent wash axe declines to
 *    resolve. Everything else in that bucket is a real result axe simply could
 *    not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less div hides, a defect that never reaches the
 *    violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectScrollersReachable(page, label);
  await expectTableScrollersTabbableIffScrolling(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE PAGE'S THESIS IS THAT THREE STREAMS LOOK IDENTICAL, and none of them
 *    exists before a click. Generate is pressed on all three, so both
 *    `.hex-output` tones and all three bit heatmaps are measured — and the
 *    statistics table that says they are indistinguishable is built and scanned
 *    rather than assumed.
 *
 *  - THE ATTACK IS A SEQUENCE, NOT A STATE. It reveals the intercepted-output
 *    block, then the progress bar, then the recovered-state line, then eleven
 *    prediction rows, then a summary whose colour depends on the tally, then a
 *    "YOUR MOVE" callout and a prediction badge on the panel above. The old
 *    gate revealed all of those containers at once and empty. Here they are
 *    reached by pressing the button and scanned once the sequence has landed.
 *
 *  - THE PREDICTION BADGE HAS TWO REACHABLE STATES, not the three the source
 *    suggests: armed, and confirmed. The third — "Prediction did not match
 *    (state changed — reseed clears the attack)" — cannot be reached, because
 *    the reseed handler clears `pendingPredictions` before the next Generate
 *    can compare against it, so the badge is hidden rather than contradicted.
 *    That is deliberate (`claims.spec.ts` asserts it: the queued prediction is
 *    "worthless and is not claimed"), so the drive follows the reachable path
 *    and asserts the badge STAYS hidden after a post-reseed Generate — which is
 *    the state that would expose the opposite bug, a stale prediction being
 *    re-claimed against a generator that has moved on.
 *
 *  - THE MODALS ARE THE ONLY DIALOGS ON THE PAGE, and each covers the document
 *    with a full-screen backdrop, so they are opened and closed one at a time
 *    and the page underneath is scanned in between.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, nothing generated');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('shared-header skip link focused');

  // This lab ships a second skip link of its own, targeting `#main-content`.
  await page.locator('#app a.skip-link').focus();
  await scanAt("lab's own skip link focused");

  // ── Generate on each of the three ────────────────────────────────────────
  const names = ['HMAC-DRBG', 'ChaCha20-DRBG', 'Dual_EC_DRBG'];
  for (const i of [HMAC, CHACHA, DUAL_EC]) {
    await panel(page, i).getByRole('button', { name: /^Generate/ }).click();
    await expect(panel(page, i).locator('.hex-output')).toHaveText(/^[0-9a-f]{40,}$/);
    await expect(panel(page, i).locator('.bit-cell').first()).toBeVisible();
    await expect(panel(page, i).locator('[role="img"]')).toHaveAttribute(
      'aria-label',
      /bits, \d+ of them 1/
    );
    await scanAt(`${names[i]} generated`);
  }

  // Reseed re-labels the counter; drive it on the honest generator, where it is
  // just bookkeeping, before driving it on the compromised one where it is the
  // defence.
  await panel(page, HMAC).getByRole('button', { name: /^Reseed/ }).click();
  await expect(panel(page, HMAC)).toContainText('(reseeded)');
  await scanAt('HMAC-DRBG reseeded');

  // ── The statistics table: the claim that all three pass ──────────────────
  await page.locator('#btn-run-stats').click();
  await expect(page.locator('.stat-table')).toBeVisible({ timeout: 180_000 });
  await expect(page.locator('.stat-table tbody tr')).toHaveCount(4);
  await scanAt('statistical tests run, all three compared');

  // ── The attack, end to end ───────────────────────────────────────────────
  await page.locator('.btn-danger').click();
  // Eleven rows: one header row plus ten predictions.
  await expect(page.locator('#attack-container .prediction-row')).toHaveCount(11, {
    timeout: 180_000,
  });
  await expect(page.locator('#attack-container')).toContainText('STATE RECOVERED');
  await expect(page.locator('#attack-container')).toContainText('YOUR MOVE');
  await expect(page.locator('#attack-container')).toContainText(/TOTAL COMPROMISE|PARTIAL/);
  await expect(page.locator('.btn-danger')).toBeEnabled();
  await scanAt('backdoor attack complete, ten predictions tabled');

  // The badge armed on the panel above, before the confirming click.
  await expect(panel(page, DUAL_EC)).toContainText("Attacker's prediction for your NEXT Generate");
  await scanAt('prediction armed on the Dual_EC panel');

  // ── The confirming click ─────────────────────────────────────────────────
  await panel(page, DUAL_EC).getByRole('button', { name: /^Generate/ }).click();
  await expect(panel(page, DUAL_EC)).toContainText('predicted this exact output');
  await scanAt('prediction confirmed by the learner’s own click');

  // ── The defence: reseeding moves the generator off the recovered state ───
  await panel(page, DUAL_EC).getByRole('button', { name: /^Reseed/ }).click();
  await expect(panel(page, DUAL_EC)).toContainText('(reseeded)');
  // `toBeHidden`, not `not.toContainText`: the reseed handler only sets
  // `display: none` on the badge, so its last message is still in the DOM. That
  // is fine for a reader — `display: none` is removed from the accessibility
  // tree as well as the frame — but it means the honest assertion is about
  // whether the badge is painted, not about what string it holds.
  await expect(page.getByText('predicted this exact output')).toBeHidden();
  await scanAt('Dual_EC reseeded, prediction badge retired');

  await panel(page, DUAL_EC).getByRole('button', { name: /^Generate/ }).click();
  // Still hidden, and that is the lab's deliberate design rather than an
  // oversight: the reseed handler discards `pendingPredictions` outright, so the
  // next Generate has nothing to compare against and claims nothing. (The
  // "Prediction did not match" branch beside it is therefore unreachable — see
  // the note in `driveAllStates`' docblock.) The assertion is worth keeping
  // because the alternative failure — a stale prediction being re-claimed
  // against a reseeded generator — would be a false security lesson, and this
  // is the state that would show it.
  await expect(page.getByText('predicted this exact output')).toBeHidden();
  await expect(panel(page, DUAL_EC).locator('.hex-output')).toHaveText(/^[0-9a-f]{40,}$/);
  await scanAt('post-reseed generate: no prediction claimed');

  // ── The two dialogs, one at a time ───────────────────────────────────────
  for (const [id, name] of [
    ['btn-kat', 'KAT'],
    ['btn-about', 'ABOUT'],
  ] as const) {
    await page.locator(`#${id}`).click();
    const backdrop = page.locator('.modal-backdrop');
    await expect(backdrop).toBeVisible();
    await expect(backdrop).toHaveAttribute('aria-modal', 'true');
    if (id === 'btn-kat') {
      await expect(backdrop.locator('.stat-table tbody tr').first()).toBeVisible({
        timeout: 60_000,
      });
      // The KAT table sits in a scroll wrapper and stays a real table. It used
      // to be given `display: block` below 640px, which drops the table role
      // in Chromium — and unlike the statistics table it carries no explicit
      // `role="table"` to put it back, so its header cells stopped being
      // headers on exactly the viewport where they matter most.
      await expect(backdrop.locator('.stat-table')).toHaveCSS('display', 'table');
      await expect(backdrop.getByRole('table')).toBeVisible();
    }
    await scanAt(`${name} modal open`);

    // Closed by its own Close button, the route a reader has.
    await backdrop.getByRole('button', { name: /close/i }).click();
    await expect(page.locator('.modal-backdrop')).toHaveCount(0);
    await scanAt(`${name} modal closed, page restored`);
  }
}
