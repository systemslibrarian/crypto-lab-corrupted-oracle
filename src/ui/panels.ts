/**
 * Three-Panel UI Logic
 *
 * Manages the HMAC-DRBG, ChaCha20-DRBG, and Dual_EC_DRBG panels,
 * along with the statistical tests panel, KAT modal, and About modal.
 */

import type { DRBGState, StatTestResult } from '../types/drbg';
import { hmacDrbgInstantiate, hmacDrbgGenerate, hmacDrbgReseed } from '../algorithms/hmac-drbg';
import { chacha20DrbgInstantiate, chacha20DrbgGenerate, chacha20DrbgReseed } from '../algorithms/chacha20-drbg';
import {
  dualEcDrbgInstantiate, dualEcDrbgGenerate, dualEcDrbgReseed,
  NIST_P, DEMO_Q, DEMO_BACKDOOR_D, dualEcGenerate, bytesToBigint
} from '../algorithms/dual-ec-drbg';
import { harvestEntropy, startMovementCollection } from '../entropy/harvester';
import { runAllTests } from '../stats/nist-tests';
import { runKATSummary } from '../kat/runner';
import { renderBitHeatmap } from './visualizer';
import { createAttackTheater } from './attack-theater';
import { recoverState } from '../attack/state-recovery';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── State ───────────────────────────────────────────────────────────
let hmacState: DRBGState | null = null;
let chacha20State: DRBGState | null = null;
let dualEcState: DRBGState | null = null;

// Store Dual_EC outputs for attack
const dualEcOutputs: Uint8Array[] = [];

export async function initUI(): Promise<void> {
  startMovementCollection();

  const app = document.getElementById('app');
  if (!app) return;

  app.innerHTML = '';

  // Skip link
  const skipLink = document.createElement('a');
  skipLink.href = '#main-content';
  skipLink.className = 'skip-link';
  skipLink.textContent = 'Skip to content';
  app.appendChild(skipLink);

  // Header
  const header = document.createElement('header');
  header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;border-bottom:1px solid var(--border-color)';
  header.innerHTML = `
    <h1 style="font-family:var(--font-mono);font-size:1.1rem;letter-spacing:0.15em;color:var(--green-clean);margin:0">
      CORRUPTED ORACLE
    </h1>
    <nav style="display:flex;gap:0.5rem" aria-label="Main navigation">
      <button class="btn" id="btn-kat" aria-label="View Known Answer Test results">KAT</button>
      <button class="btn" id="btn-about" aria-label="About this demonstration">ABOUT</button>
    </nav>
  `;
  app.appendChild(header);

  // Main content
  const main = document.createElement('main');
  main.id = 'main-content';
  main.style.cssText = 'padding:1rem;flex:1';

  // Three-panel grid
  const panelGrid = document.createElement('div');
  panelGrid.className = 'three-panel';
  panelGrid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem';

  const hmacPanel = createAlgoPanel('HMAC-DRBG', '✅', 'NIST SP 800-90A', 'clean');
  const chachaPanel = createAlgoPanel('ChaCha20-DRBG', '✅', 'Modern / RFC 8439', 'clean');
  const dualEcPanel = createAlgoPanel('Dual_EC_DRBG', '⚠️', 'COMPROMISED', 'corrupt');

  panelGrid.appendChild(hmacPanel.container);
  panelGrid.appendChild(chachaPanel.container);
  panelGrid.appendChild(dualEcPanel.container);
  main.appendChild(panelGrid);

  // Attack theater container (below Dual_EC panel)
  const attackContainer = document.createElement('div');
  attackContainer.id = 'attack-container';
  attackContainer.style.display = 'none';
  main.appendChild(attackContainer);

  // Statistical tests section
  const statsSection = document.createElement('section');
  statsSection.setAttribute('aria-label', 'Statistical test results');
  statsSection.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        Statistical Tests (SP 800-22)
        <button class="btn" id="btn-run-stats" style="margin-left:auto;font-size:0.7rem">Run Tests</button>
      </div>
      <div id="stats-output" style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary)">
        Generate output from all three algorithms, then run statistical tests.
      </div>
    </div>
  `;
  main.appendChild(statsSection);

  // Educational notice
  const notice = document.createElement('div');
  notice.style.cssText = 'margin-top:1rem;padding:0.75rem;border:1px solid var(--amber-warn);background:rgba(255,170,0,0.05);font-family:var(--font-mono);font-size:0.75rem;color:var(--amber-warn)';
  notice.innerHTML = '⚠ NOTICE: Dual_EC_DRBG passes all statistical tests. You cannot detect this backdoor by looking at output.';
  notice.setAttribute('role', 'alert');
  main.appendChild(notice);

  app.appendChild(main);

  // ─── Initialize DRBGs ────────────────────────────────────────────
  const entropy = await harvestEntropy(48);
  const nonce = await harvestEntropy(16);
  const personalization = new Uint8Array(0);

  hmacState = await hmacDrbgInstantiate(entropy.slice(0, 32), nonce, personalization, 256);
  chacha20State = await chacha20DrbgInstantiate(entropy.slice(0, 32), nonce, personalization, 256);
  dualEcState = await dualEcDrbgInstantiate(entropy.slice(0, 32), nonce, personalization, 256);

  // ─── Wire up buttons ─────────────────────────────────────────────
  hmacPanel.generateBtn.addEventListener('click', async () => {
    if (!hmacState) return;
    const result = await hmacDrbgGenerate(hmacState, 256, new Uint8Array(0));
    hmacState = result.state;
    hmacPanel.output.textContent = toHex(result.result.bytes);
    hmacPanel.stateDisplay.textContent = `reseed_counter: ${result.state.reseedCounter}`;
    renderBitHeatmap(hmacPanel.heatmap, result.result.bytes, 'clean');
  });

  hmacPanel.reseedBtn.addEventListener('click', async () => {
    if (!hmacState) return;
    const ent = await harvestEntropy(32);
    hmacState = await hmacDrbgReseed(hmacState, ent, new Uint8Array(0));
    hmacPanel.stateDisplay.textContent = `reseed_counter: ${hmacState.reseedCounter} (reseeded)`;
  });

  chachaPanel.generateBtn.addEventListener('click', async () => {
    if (!chacha20State) return;
    const result = await chacha20DrbgGenerate(chacha20State, 256, new Uint8Array(0));
    chacha20State = result.state;
    chachaPanel.output.textContent = toHex(result.result.bytes);
    chachaPanel.stateDisplay.textContent = `reseed_counter: ${result.state.reseedCounter}`;
    renderBitHeatmap(chachaPanel.heatmap, result.result.bytes, 'clean');
  });

  chachaPanel.reseedBtn.addEventListener('click', async () => {
    if (!chacha20State) return;
    const ent = await harvestEntropy(32);
    chacha20State = await chacha20DrbgReseed(chacha20State, ent, new Uint8Array(0));
    chachaPanel.stateDisplay.textContent = `reseed_counter: ${chacha20State.reseedCounter} (reseeded)`;
  });

  dualEcPanel.generateBtn.addEventListener('click', async () => {
    if (!dualEcState) return;
    const result = await dualEcDrbgGenerate(dualEcState, 240, new Uint8Array(0), NIST_P, DEMO_Q);
    dualEcState = result.state;
    dualEcOutputs.push(result.result.bytes);
    dualEcPanel.output.textContent = toHex(result.result.bytes);
    dualEcPanel.output.className = 'hex-output corrupted';
    dualEcPanel.stateDisplay.textContent = `reseed_counter: ${result.state.reseedCounter}`;
    renderBitHeatmap(dualEcPanel.heatmap, result.result.bytes, 'corrupt');
  });

  dualEcPanel.reseedBtn.addEventListener('click', async () => {
    if (!dualEcState) return;
    const ent = await harvestEntropy(32);
    dualEcState = await dualEcDrbgReseed(dualEcState, ent, new Uint8Array(0));
    dualEcPanel.stateDisplay.textContent = `reseed_counter: ${dualEcState.reseedCounter} (reseeded)`;
    dualEcOutputs.length = 0;
  });

  // Attack button
  const attackBtn = dualEcPanel.container.querySelector('.btn-danger') as HTMLButtonElement;
  if (attackBtn) {
    attackBtn.addEventListener('click', async () => {
      if (!dualEcState) return;

      attackBtn.disabled = true;
      attackBtn.textContent = 'ATTACKING...';
      attackContainer.style.display = 'block';
      attackContainer.innerHTML = '';

      const theater = createAttackTheater(attackContainer);

      // Generate two fresh outputs for the attack
      const s = bytesToBigint(dualEcState.internalState);
      const round1 = dualEcGenerate(s, NIST_P, DEMO_Q);
      const round2 = dualEcGenerate(round1.nextState, NIST_P, DEMO_Q);

      // Now run the attack with the two outputs
      const result = await recoverState(
        round1.output,
        round2.output,
        DEMO_BACKDOOR_D,
        NIST_P,
        DEMO_Q,
        (event) => {
          theater.handleEvent(event);

          // For predictions, also show actual values
          if (event.type === 'prediction' && event.predictedOutput) {
            // Generate actual to compare
          }
        },
        10
      );

      if (result.success) {
        // Generate actuals to populate the display
        let verifyState = result.recoveredState!;
        // Skip two states (the ones we used for attack)
        const skip1 = dualEcGenerate(verifyState, NIST_P, DEMO_Q);
        verifyState = skip1.nextState;

        for (let i = 0; i < result.predictedOutputs.length; i++) {
          const actual = dualEcGenerate(verifyState, NIST_P, DEMO_Q);
          theater.handleEvent({
            type: 'prediction',
            candidatesTried: result.candidatesTried,
            totalCandidates: 65536,
            predictedOutput: toHex(result.predictedOutputs[i]),
            actualOutput: toHex(actual.output),
            match: toHex(result.predictedOutputs[i]) === toHex(actual.output),
          });
          verifyState = actual.nextState;
        }
      } else {
        theater.handleEvent({
          type: 'progress',
          candidatesTried: result.candidatesTried,
          totalCandidates: 65536,
        });
        const failMsg = document.createElement('div');
        failMsg.style.cssText = 'color:var(--amber-warn);font-family:var(--font-mono);font-size:0.8rem;margin-top:0.5rem';
        failMsg.textContent = 'Attack failed — try again with fresh output.';
        attackContainer.appendChild(failMsg);
      }

      attackBtn.disabled = false;
      attackBtn.textContent = 'TRIGGER ATTACK';
    });
  }

  // Statistical tests
  document.getElementById('btn-run-stats')?.addEventListener('click', async () => {
    const statsOutput = document.getElementById('stats-output');
    if (!statsOutput) return;

    statsOutput.textContent = 'Running statistical tests on 125,000 bytes per algorithm...';

    // Generate large samples
    const sampleSize = 125_000; // 1,000,000 bits
    const sampleBits = sampleSize * 8;

    let hmacSample = new Uint8Array(0);
    let chachaSample = new Uint8Array(0);
    let dualEcSample = new Uint8Array(0);

    // HMAC-DRBG sample
    if (hmacState) {
      let st = hmacState;
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (total < sampleSize) {
        const chunkSize = Math.min(256, sampleSize - total);
        const res = await hmacDrbgGenerate(st, chunkSize * 8, new Uint8Array(0));
        if (res.result.reseedRequired) {
          st = await hmacDrbgReseed(st, await harvestEntropy(32), new Uint8Array(0));
          continue;
        }
        st = res.state;
        chunks.push(res.result.bytes);
        total += res.result.bytes.length;
      }
      hmacSample = concatArrays(chunks).slice(0, sampleSize);
    }

    // ChaCha20 sample
    if (chacha20State) {
      const res = await chacha20DrbgGenerate(chacha20State, sampleBits, new Uint8Array(0));
      chachaSample = res.result.bytes.slice(0, sampleSize);
    }

    // Dual_EC sample
    if (dualEcState) {
      let st = dualEcState;
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (total < sampleSize) {
        const res = await dualEcDrbgGenerate(st, 240, new Uint8Array(0), NIST_P, DEMO_Q);
        st = res.state;
        chunks.push(res.result.bytes);
        total += res.result.bytes.length;
      }
      dualEcSample = concatArrays(chunks).slice(0, sampleSize);
    }

    // Run tests
    const hmacResults = runAllTests(hmacSample);
    const chachaResults = runAllTests(chachaSample);
    const dualEcResults = runAllTests(dualEcSample);

    // Render table
    renderStatTable(statsOutput, hmacResults, chachaResults, dualEcResults);
  });

  // KAT modal
  document.getElementById('btn-kat')?.addEventListener('click', async () => {
    showKATModal();
  });

  // About modal
  document.getElementById('btn-about')?.addEventListener('click', () => {
    showAboutModal();
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────

function createAlgoPanel(name: string, icon: string, subtitle: string, variant: 'clean' | 'corrupt') {
  const container = document.createElement('div');
  container.className = 'panel';
  if (variant === 'corrupt') {
    container.style.borderColor = 'var(--red-dim)';
  }

  const header = document.createElement('div');
  header.className = 'panel-header';
  header.innerHTML = `<span class="status-icon">${icon}</span> ${name}`;

  const subtitleEl = document.createElement('div');
  subtitleEl.style.cssText = 'font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em';
  subtitleEl.textContent = subtitle;

  const btnRow = document.createElement('div');
  btnRow.style.cssText = 'display:flex;gap:0.5rem;flex-wrap:wrap';

  const generateBtn = document.createElement('button');
  generateBtn.className = 'btn';
  generateBtn.textContent = 'Generate';
  generateBtn.setAttribute('aria-label', `Generate random bytes with ${name}`);

  const reseedBtn = document.createElement('button');
  reseedBtn.className = 'btn';
  reseedBtn.textContent = 'Reseed';
  reseedBtn.setAttribute('aria-label', `Reseed ${name}`);

  btnRow.appendChild(generateBtn);
  btnRow.appendChild(reseedBtn);

  if (variant === 'corrupt') {
    const attackBtn = document.createElement('button');
    attackBtn.className = 'btn btn-danger';
    attackBtn.textContent = 'TRIGGER ATTACK';
    attackBtn.setAttribute('aria-label', 'Trigger backdoor state recovery attack');
    btnRow.appendChild(attackBtn);
  }

  const stateDisplay = document.createElement('div');
  stateDisplay.style.cssText = 'font-family:var(--font-mono);font-size:0.7rem;color:var(--text-secondary)';
  stateDisplay.textContent = 'Not yet instantiated';

  const output = document.createElement('div');
  output.className = `hex-output${variant === 'corrupt' ? ' corrupted' : ''}`;
  output.setAttribute('role', 'status');
  output.setAttribute('aria-live', 'polite');
  output.setAttribute('aria-label', `${name} output`);
  output.textContent = '—';

  const heatmap = document.createElement('div');
  heatmap.setAttribute('aria-label', `${name} bit pattern`);

  container.appendChild(header);
  container.appendChild(subtitleEl);
  container.appendChild(btnRow);
  container.appendChild(stateDisplay);
  container.appendChild(output);
  container.appendChild(heatmap);

  return { container, generateBtn, reseedBtn, output, stateDisplay, heatmap };
}

function renderStatTable(
  container: HTMLElement,
  hmacResults: StatTestResult[],
  chachaResults: StatTestResult[],
  dualEcResults: StatTestResult[]
): void {
  const table = document.createElement('table');
  table.className = 'stat-table';
  table.setAttribute('role', 'table');
  table.setAttribute('aria-label', 'Statistical test results comparison');

  const thead = document.createElement('thead');
  thead.innerHTML = `<tr>
    <th>Test</th>
    <th>HMAC-DRBG</th>
    <th>ChaCha20-DRBG</th>
    <th>Dual_EC_DRBG</th>
  </tr>`;
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (let i = 0; i < hmacResults.length; i++) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${hmacResults[i].name}</td>
      <td>${formatStatResult(hmacResults[i])}</td>
      <td>${formatStatResult(chachaResults[i])}</td>
      <td>${formatStatResult(dualEcResults[i])}</td>
    `;
    tbody.appendChild(row);
  }
  table.appendChild(tbody);

  container.innerHTML = '';
  container.appendChild(table);
}

function formatStatResult(result: StatTestResult): string {
  const icon = result.passed ? '✅' : '❌';
  return `${icon} p=${result.pValue.toFixed(2)}`;
}

function concatArrays(arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

async function showKATModal(): Promise<void> {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.setAttribute('role', 'dialog');
  backdrop.setAttribute('aria-modal', 'true');
  backdrop.setAttribute('aria-label', 'Known Answer Test Results');

  const content = document.createElement('div');
  content.className = 'modal-content';
  content.innerHTML = '<div class="panel-header">Known Answer Test Results</div><p style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary);margin:0.5rem 0">Running HMAC-DRBG KAT vectors...</p>';

  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn';
  closeBtn.textContent = 'Close';
  closeBtn.style.marginTop = '1rem';
  closeBtn.setAttribute('aria-label', 'Close KAT results modal');

  content.appendChild(closeBtn);
  backdrop.appendChild(content);
  document.body.appendChild(backdrop);

  closeBtn.addEventListener('click', () => backdrop.remove());
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.addEventListener('keydown', function handler(e) {
    if (e.key === 'Escape') { backdrop.remove(); document.removeEventListener('keydown', handler); }
  });

  // Run KAT
  const summary = await runKATSummary();
  const p = content.querySelector('p');
  if (p) {
    p.textContent = `${summary.passed}/${summary.total} vectors passed`;
    if (summary.failed > 0) {
      p.style.color = 'var(--amber-warn)';
      p.textContent += ' — NEEDS_VERIFICATION: vectors must be verified against NIST CAVS 14.3';
    }
  }

  const table = document.createElement('table');
  table.className = 'stat-table';
  table.style.marginTop = '0.75rem';
  table.innerHTML = `<thead><tr><th>Vector ID</th><th>Status</th><th>Expected (first 16)</th><th>Actual (first 16)</th></tr></thead>`;
  const tbody = document.createElement('tbody');
  for (const r of summary.results) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${r.vectorId}</td>
      <td>${r.passed ? '✅ PASS' : '❌ FAIL'}</td>
      <td style="font-family:var(--font-mono);font-size:0.65rem">${r.expected.substring(0, 16)}...</td>
      <td style="font-family:var(--font-mono);font-size:0.65rem">${r.actual.substring(0, 16)}...</td>
    `;
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  content.insertBefore(table, closeBtn);

  const sourceNote = document.createElement('p');
  sourceNote.style.cssText = 'font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-top:0.5rem';
  sourceNote.textContent = 'Vectors: NIST CAVS 14.3 HMAC_DRBG SHA-256 (NEEDS_VERIFICATION)';
  content.insertBefore(sourceNote, closeBtn);

  closeBtn.focus();
}

function showAboutModal(): void {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.setAttribute('role', 'dialog');
  backdrop.setAttribute('aria-modal', 'true');
  backdrop.setAttribute('aria-label', 'About Corrupted Oracle');

  const content = document.createElement('div');
  content.className = 'modal-content';
  content.style.maxWidth = '700px';
  content.innerHTML = `
    <div class="panel-header" style="margin-bottom:1rem">About Corrupted Oracle</div>

    <div style="font-size:0.85rem;line-height:1.7;color:var(--text-primary)">
      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--green-clean);margin:0 0 0.5rem">What is Dual_EC_DRBG?</h2>
      <p style="margin-bottom:0.75rem">
        Dual_EC_DRBG (Dual Elliptic Curve Deterministic Random Bit Generator) was a
        pseudorandom number generator standardized by NIST in SP 800-90A (2006). Unlike
        other DRBGs in the standard, it uses elliptic curve arithmetic: internal state
        is updated via scalar multiplication of two "randomly chosen" points P and Q on
        the P-256 curve.
      </p>
      <p style="margin-bottom:1rem">
        The critical vulnerability: if someone knows the scalar <em>e</em> such that
        Q = e·P, they can recover the DRBG's internal state from a single output block.
        From that point forward, every future output is predictable. The generator's
        output passes all standard statistical tests — the backdoor is mathematically
        invisible to black-box analysis.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--red-corrupt);margin:0 0 0.5rem">The NSA Connection</h2>
      <p style="margin-bottom:0.75rem">
        In September 2013, Reuters reported that the NSA had paid RSA Security $10 million
        to make Dual_EC_DRBG the default random number generator in their BSAFE toolkit,
        the most widely used commercial crypto library at the time. Documents leaked by
        Edward Snowden confirmed that the NSA had inserted a backdoor into a NIST standard.
      </p>
      <p style="margin-bottom:1rem">
        Cryptographers had suspected the P-Q relationship since 2007 (Shumow and Ferguson,
        Crypto rump session). NIST withdrew Dual_EC_DRBG from SP 800-90A in 2014.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--amber-warn);margin:0 0 0.5rem">Demo vs. Reality</h2>
      <p style="margin-bottom:1rem">
        This demonstration uses a <strong>demo backdoor scalar</strong> — we generate our own
        Q = e·P where we know e. This proves the attack mechanism works. We do not claim to
        have recovered the actual scalar relationship between NIST's published P and Q values.
        The NIST Q point is displayed for reference, but the attack runs against our demo Q.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--text-secondary);margin:0 0 0.5rem">References</h2>
      <ul style="list-style:none;padding:0;font-family:var(--font-mono);font-size:0.75rem;color:var(--blue-info)">
        <li style="margin-bottom:0.3rem">
          <a href="https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final" target="_blank" rel="noopener" style="color:inherit">
            NIST SP 800-90A Rev 1 (post-withdrawal, Dual_EC removed)
          </a>
        </li>
        <li style="margin-bottom:0.3rem">
          <a href="https://projectbullrun.org/dual-ec/documents/dual-ec-20150731.pdf" target="_blank" rel="noopener" style="color:inherit">
            Bernstein, Lange, Niederhagen — "Dual EC: A Standardized Back Door" (2015)
          </a>
        </li>
        <li style="margin-bottom:0.3rem">
          <a href="https://www.reuters.com/article/us-usa-security-rsa-idUSBRE9BJ1C220131220/" target="_blank" rel="noopener" style="color:inherit">
            Reuters (2013) — "Secret contract tied NSA and security industry pioneer"
          </a>
        </li>
        <li style="margin-bottom:0.3rem">
          <a href="https://rump2007.cr.yp.to/15-shumow.pdf" target="_blank" rel="noopener" style="color:inherit">
            Shumow & Ferguson — "On the Possibility of a Back Door in the NIST SP800-90 Dual Ec Prng" (2007)
          </a>
        </li>
      </ul>
    </div>
  `;

  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn';
  closeBtn.textContent = 'Close';
  closeBtn.style.marginTop = '1rem';
  closeBtn.setAttribute('aria-label', 'Close about modal');
  closeBtn.addEventListener('click', () => backdrop.remove());

  content.appendChild(closeBtn);
  backdrop.appendChild(content);
  document.body.appendChild(backdrop);

  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.addEventListener('keydown', function handler(e) {
    if (e.key === 'Escape') { backdrop.remove(); document.removeEventListener('keydown', handler); }
  });

  closeBtn.focus();
}
