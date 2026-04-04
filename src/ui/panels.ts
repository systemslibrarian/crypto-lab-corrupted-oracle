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
  header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;border-bottom:1px solid var(--border-color);flex-wrap:wrap;gap:0.5rem';
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
  main.style.cssText = 'padding:1rem 1.5rem;flex:1';

  // ─── Intro Section ─────────────────────────────────────────────
  const intro = document.createElement('section');
  intro.style.cssText = 'margin-bottom:1.5rem;max-width:900px';
  intro.innerHTML = `
    <p style="font-size:0.95rem;line-height:1.8;color:var(--text-primary);margin-bottom:0.75rem">
      In 2006, NIST published a pseudorandom number generator called <strong style="color:var(--red-corrupt)">Dual_EC_DRBG</strong>.
      It looked like every other standard. It passed every statistical test. But it had a secret:
      whoever chose its internal constants could predict every "random" number it would ever produce.
    </p>
    <p style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary);margin-bottom:0.75rem">
      This page runs three real pseudorandom number generators side by side.
      Two are honest. One is compromised. <strong style="color:var(--text-primary)">Click Generate</strong> on each
      to produce random bytes, then <strong style="color:var(--text-primary)">Run Tests</strong> below to see that all three
      pass the same statistical tests. Finally, <strong style="color:var(--red-corrupt)">Trigger Attack</strong> on the
      compromised generator — and watch as its future is predicted with 100% accuracy.
    </p>
    <p style="font-size:0.8rem;line-height:1.6;color:var(--text-muted)">
      Everything runs in your browser. No server. No shortcuts. Real elliptic curve math on real NIST constants.
    </p>
  `;
  main.appendChild(intro);

  // Three-panel grid
  const panelGrid = document.createElement('div');
  panelGrid.className = 'three-panel';
  panelGrid.setAttribute('role', 'region');
  panelGrid.setAttribute('aria-label', 'Algorithm comparison panels');
  panelGrid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;margin-bottom:1.5rem';

  const hmacPanel = createAlgoPanel(
    'HMAC-DRBG', '✅', 'NIST SP 800-90A §10.1.2', 'clean',
    'The workhorse DRBG still in the NIST standard. Uses HMAC-SHA-256 in a feedback loop: '
    + 'the output of each HMAC call feeds back into the key and state for the next. '
    + 'No known weaknesses. This is what "doing it right" looks like.'
  );
  const chachaPanel = createAlgoPanel(
    'ChaCha20-DRBG', '✅', 'Modern / RFC 8439', 'clean',
    'Based on the ChaCha20 stream cipher — the same construction behind OpenBSD\'s arc4random '
    + 'and Linux\'s getrandom(). Fast, simple, and battle-tested. Uses the keystream directly '
    + 'as random output. No algebraic structure to exploit.'
  );
  const dualEcPanel = createAlgoPanel(
    'Dual_EC_DRBG', '⚠️', 'COMPROMISED', 'corrupt',
    'The backdoored generator. Uses two points P and Q on an elliptic curve. '
    + 'Each output leaks enough of the internal state that anyone who knows '
    + 'the secret relationship between P and Q can recover the full state '
    + 'and predict every future output. NIST withdrew it in 2014.'
  );

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
      <p style="font-size:0.8rem;line-height:1.6;color:var(--text-secondary);margin:0.5rem 0">
        These are four tests from the NIST statistical test suite, designed to detect
        non-randomness in binary sequences. They check for biased bit frequencies,
        unexpected run lengths, and block-level anomalies. A truly random sequence should
        pass all four with p-values above 0.01.
      </p>
      <p style="font-size:0.8rem;line-height:1.6;color:var(--text-secondary);margin-bottom:0.5rem">
        <strong style="color:var(--text-primary)">The critical lesson:</strong> click "Run Tests" and watch
        Dual_EC_DRBG pass every single one. The backdoor does not affect the statistical
        properties of the output — it lives in the <em>algebraic structure</em> that maps
        output back to internal state, not in any detectable pattern.
      </p>
      <div id="stats-output" style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary)">
        Generate output from all three algorithms, then run statistical tests.
      </div>
    </div>
  `;
  main.appendChild(statsSection);

  // Educational notice
  const notice = document.createElement('div');
  notice.style.cssText = 'margin-top:1rem;padding:1rem;border:1px solid var(--amber-warn);background:rgba(255,170,0,0.05);font-size:0.85rem;line-height:1.7';
  notice.setAttribute('role', 'alert');
  notice.innerHTML = `
    <div style="color:var(--amber-warn);font-family:var(--font-mono);font-weight:600;margin-bottom:0.5rem">⚠ WHY THIS MATTERS</div>
    <p style="color:var(--text-primary);margin-bottom:0.5rem">
      Every standard randomness test says Dual_EC_DRBG output looks perfectly random.
      An auditor running these tests would see nothing wrong. A code reviewer looking at
      the implementation would see a standard NIST algorithm used correctly.
    </p>
    <p style="color:var(--text-secondary)">
      But the entity that chose the point Q — widely believed to be the NSA — could silently
      decrypt TLS sessions, predict authentication tokens, and recover private keys generated
      by any system using this "standard" generator. The backdoor is invisible unless you
      understand the math. That is what this demo shows.
    </p>
  `;
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
      announce('Backdoor attack started. Brute-forcing 65,536 candidates.');
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
        // Recovered state is s₂. Predictions were generated starting from s₂.
        // Verify by independently generating from s₂.
        let verifyState = result.recoveredState!;

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

      announce(result.success ? 'Attack complete. All predictions matched.' : 'Attack failed.');
      attackBtn.disabled = false;
      attackBtn.textContent = 'TRIGGER ATTACK';
    });
  }

  // Statistical tests
  document.getElementById('btn-run-stats')?.addEventListener('click', async () => {
    const statsOutput = document.getElementById('stats-output');
    if (!statsOutput) return;

    statsOutput.textContent = 'Running statistical tests on 125,000 bytes per algorithm...';
    announce('Running statistical tests.');

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
    announce('Statistical tests complete. Results displayed in table.');
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

function createAlgoPanel(name: string, icon: string, subtitle: string, variant: 'clean' | 'corrupt', description?: string) {
  const container = document.createElement('div');
  container.className = 'panel';
  if (variant === 'corrupt') {
    container.style.borderColor = 'var(--red-dim)';
  }

  const header = document.createElement('h2');
  header.className = 'panel-header';
  header.style.fontSize = '0.85rem';
  header.innerHTML = `<span class="status-icon" aria-hidden="true">${icon}</span> ${name}`;

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

  if (description) {
    const desc = document.createElement('p');
    desc.style.cssText = 'font-size:0.78rem;line-height:1.6;color:var(--text-secondary);margin:0.25rem 0 0.5rem';
    desc.textContent = description;
    container.appendChild(desc);
  }

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

  closeBtn.addEventListener('click', () => { backdrop.remove(); restoreFocus(); });
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) { backdrop.remove(); restoreFocus(); } });
  const previousFocus = document.activeElement as HTMLElement | null;
  function restoreFocus() { previousFocus?.focus(); }
  document.addEventListener('keydown', function handler(e) {
    if (e.key === 'Escape') { backdrop.remove(); restoreFocus(); document.removeEventListener('keydown', handler); }
    if (e.key === 'Tab') { trapFocus(e, content); }
  });

  // Run KAT
  const summary = await runKATSummary();
  const p = content.querySelector('p');
  if (p) {
    p.textContent = `${summary.passed}/${summary.total} vectors passed`;
    if (summary.failed > 0) {
      p.style.color = 'var(--amber-warn)';
      p.textContent += ' — check implementation against NIST CAVS expected values';
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
  sourceNote.textContent = 'Vectors: NIST CAVS 14.3 HMAC_DRBG(SHA-256), PR=False, Count 0–4';
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
      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--green-clean);margin:0 0 0.5rem">What is a DRBG?</h2>
      <p style="margin-bottom:0.75rem">
        A Deterministic Random Bit Generator (DRBG) is an algorithm that takes a short
        secret seed and stretches it into a long stream of bits that <em>appear</em> random.
        Every TLS handshake, every cryptographic key, every session token depends on a DRBG.
        If an attacker can predict a DRBG's output, they can silently break encryption,
        forge signatures, and impersonate users — all without leaving a trace.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--green-clean);margin:0 0 0.5rem">What is Dual_EC_DRBG?</h2>
      <p style="margin-bottom:0.75rem">
        Dual_EC_DRBG (Dual Elliptic Curve Deterministic Random Bit Generator) was one of
        four DRBGs standardized by NIST in SP 800-90A (2006). Unlike HMAC-DRBG or CTR-DRBG,
        which use symmetric cryptography, Dual_EC_DRBG uses <em>elliptic curve</em> arithmetic:
        it maintains a secret scalar <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">s</code>
        and updates it via P-multiplication, then derives output via Q-multiplication.
        P is the standard generator; Q was published by NIST as a "randomly selected" constant.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--red-corrupt);margin:0 0 0.5rem">How the Backdoor Works</h2>
      <p style="margin-bottom:0.5rem">
        The algorithm works in three steps each time it generates output:
      </p>
      <ol style="margin:0 0 0.75rem 1.2rem;line-height:1.8;color:var(--text-primary)">
        <li>Update state: <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">s = (s_old · P).x</code> — multiply old state by P, take x-coordinate</li>
        <li>Compute output: <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">r = (s · Q).x</code> — multiply new state by Q</li>
        <li><strong>Output</strong> the low 30 bytes of <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">r</code> (drop the top 16 bits)</li>
      </ol>
      <p style="margin-bottom:0.75rem">
        The crucial leak: each output reveals 240 of the 256 bits of <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">r</code>.
        That leaves only 2<sup>16</sup> = 65,536 possibilities for the full x-coordinate of the
        point R = s·Q. If you know the
        secret scalar <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">d = e⁻¹ mod n</code>
        where <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">Q = e · P</code>,
        you can compute <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">d · R = d · (s·Q) = s · (d·Q) = s · P</code>.
        And <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">(s · P).x</code> is exactly
        the next internal state — giving you every future output forever.
      </p>
      <p style="margin-bottom:0.5rem;color:var(--red-corrupt)">
        65,536 guesses. One scalar multiplication per guess. A modern laptop can do it in under a second.
      </p>
      <p style="margin-bottom:1rem;font-size:0.8rem;color:var(--text-secondary)">
        <strong>Without</strong> knowing <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">d</code>,
        computing d·R requires solving the elliptic curve discrete log problem —
        computationally infeasible with current technology. That's why only the entity that
        chose Q can exploit the backdoor.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--red-corrupt);margin:0 0 0.5rem">The NSA Connection</h2>
      <p style="margin-bottom:0.75rem">
        In September 2013, Reuters reported that the NSA had paid RSA Security $10 million
        to make Dual_EC_DRBG the default random number generator in their BSAFE toolkit —
        the most widely used commercial crypto library at the time. Documents leaked by
        Edward Snowden confirmed that the NSA had deliberately inserted a backdoor into a
        NIST-published standard.
      </p>
      <p style="margin-bottom:0.5rem">
        The suspicion was not new. In August 2007, cryptographers Dan Shumow and Niels
        Ferguson gave a talk at the Crypto conference rump session titled <em>"On the
        Possibility of a Back Door in the NIST SP800-90 Dual Ec Prng"</em>. They demonstrated
        that the P-Q relationship was exactly the kind of structure that would enable a
        backdoor — but could not prove one existed because nobody outside the NSA knew
        whether a secret <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">e</code>
        had been chosen.
      </p>
      <p style="margin-bottom:1rem">
        NIST withdrew Dual_EC_DRBG from SP 800-90A in June 2014. By then, it had been
        a published standard for eight years.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--amber-warn);margin:0 0 0.5rem">Why Can't You Just Test for It?</h2>
      <p style="margin-bottom:1rem">
        Because the backdoor doesn't affect the <em>distribution</em> of the output bits.
        The output of Dual_EC_DRBG is statistically indistinguishable from a truly random
        sequence — it passes monobit tests, runs tests, block frequency tests, everything.
        The weakness is <em>structural</em>: it's in the algebraic relationship between the
        curve points, not in any pattern in the bits. No amount of output analysis will find
        it. You have to understand the math, and then you have to know (or suspect) that
        someone chose Q maliciously.
      </p>

      <h2 style="font-family:var(--font-mono);font-size:0.9rem;color:var(--amber-warn);margin:0 0 0.5rem">Demo vs. Reality</h2>
      <p style="margin-bottom:0.5rem">
        This demonstration uses a <strong>known demo backdoor scalar</strong> — we pick our own
        <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">e</code>
        and compute <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">Q = e · P</code>
        ourselves. This proves the attack mechanism works mathematically.
      </p>
      <p style="margin-bottom:1rem">
        We do <strong>not</strong> claim to have recovered the actual scalar relationship between
        NIST's published P and Q values. The real NIST Q point is shown for reference, but
        the attack runs against our demo Q. The real-world implication is this: whoever chose
        the NIST Q point — and the NSA is widely believed to have done so — would have known
        <code style="font-size:0.8rem;background:var(--bg-secondary);padding:2px 5px">e</code>
        and could have silently exploited every system that used the standard constants.
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
  const previousFocus = document.activeElement as HTMLElement | null;
  function restoreFocus() { previousFocus?.focus(); }
  closeBtn.addEventListener('click', () => { backdrop.remove(); restoreFocus(); });

  content.appendChild(closeBtn);
  backdrop.appendChild(content);
  document.body.appendChild(backdrop);

  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) { backdrop.remove(); restoreFocus(); } });
  document.addEventListener('keydown', function handler(e) {
    if (e.key === 'Escape') { backdrop.remove(); restoreFocus(); document.removeEventListener('keydown', handler); }
    if (e.key === 'Tab') { trapFocus(e, content); }
  });

  closeBtn.focus();
}

/** Trap focus inside a container for modal accessibility (WCAG 2.4.3) */
function trapFocus(e: KeyboardEvent, container: HTMLElement): void {
  const focusable = container.querySelectorAll<HTMLElement>(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

/** Announce a message to screen readers */
function announce(message: string): void {
  const el = document.getElementById('sr-announcer');
  if (el) {
    el.textContent = '';
    requestAnimationFrame(() => { el.textContent = message; });
  }
}
