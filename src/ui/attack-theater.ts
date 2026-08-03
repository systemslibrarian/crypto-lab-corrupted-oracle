/**
 * Attack Theater — Live Backdoor Display
 *
 * Renders the Dual_EC_DRBG backdoor attack sequence with dramatic
 * visual effects: pulsing red borders, typewriter text, progress bar,
 * and prediction verification display.
 */

import type { AttackEvent } from '../types/drbg';

export function createAttackTheater(container: HTMLElement): {
  setIntercepted: (hexA: string, hexB: string) => void;
  armNextClick: (predictedHex: string) => void;
  handleEvent: (event: AttackEvent) => void;
  reset: () => void;
} {
  const theater = document.createElement('div');
  theater.className = 'attack-overlay panel';
  theater.setAttribute('role', 'status');
  theater.setAttribute('aria-live', 'polite');
  theater.setAttribute('aria-label', 'Backdoor attack progress');

  // Pre-attack explainer
  const explainer = document.createElement('div');
  explainer.style.cssText = 'font-size:0.8rem;line-height:1.7;color:var(--text-secondary);margin-bottom:0.75rem';
  explainer.innerHTML = `
    <p style="margin-bottom:0.5rem;color:var(--text-primary)"><strong>What's happening now:</strong></p>
    <ol style="margin:0 0 0.5rem 1.2rem;line-height:1.8">
      <li>The attack engine captured <strong>two consecutive 30-byte output blocks</strong> of the output you generated.</li>
      <li>Each output reveals 240 of 256 bits of <em>r = (s · Q).x</em>.
      The missing 16 bits mean 65,536 possible x-coordinates for the output point R = s·Q.</li>
      <li>For each candidate point R on the curve, the engine computes
      <strong><em>d</em> · R</strong> — this is the critical backdoor step.
      Since <em>d = e<sup>−1</sup></em> and <em>Q = e·P</em>, we get
      <em>d·(s·Q) = s·(d·Q) = s·P</em> — the next internal state.</li>
      <li>The engine verifies by computing what the <em>next</em> output <strong>would</strong> be
      from the candidate state, and comparing to the actual second block.</li>
    </ol>
    <p style="font-size:0.75rem;color:var(--text-muted)">
      <strong>Why this requires the secret:</strong> Without knowing <em>d</em>, computing
      <em>d·R</em> requires solving the elliptic curve discrete log problem — computationally
      infeasible. Only the entity that chose Q (and thus knows <em>e</em>) can perform this step.
    </p>
  `;
  theater.appendChild(explainer);

  // Intercepted-output display + a visual of the 16-bit leak.
  const interceptedEl = document.createElement('div');
  interceptedEl.style.cssText = 'font-family:var(--font-mono);font-size:0.68rem;line-height:1.6;margin-bottom:0.6rem;display:none;overflow-wrap:anywhere';
  theater.appendChild(interceptedEl);

  const statusLine = document.createElement('div');
  statusLine.className = 'panel-header';
  statusLine.style.color = 'var(--red-corrupt)';
  statusLine.textContent = 'INTERCEPTING OUTPUT BLOCKS...';

  const progressContainer = document.createElement('div');
  progressContainer.style.marginTop = '0.5rem';

  const progressLabel = document.createElement('div');
  progressLabel.style.fontFamily = 'var(--font-mono)';
  progressLabel.style.fontSize = '0.7rem';
  progressLabel.style.color = 'var(--text-secondary)';
  progressLabel.style.marginBottom = '0.25rem';

  const progressBar = document.createElement('div');
  progressBar.className = 'progress-bar';
  progressBar.setAttribute('role', 'progressbar');
  progressBar.setAttribute('aria-valuemin', '0');
  progressBar.setAttribute('aria-valuemax', '100');
  progressBar.setAttribute('aria-valuenow', '0');
  progressBar.setAttribute('aria-label', 'Attack brute-force progress');
  const progressFill = document.createElement('div');
  progressFill.className = 'progress-fill';
  progressFill.style.width = '0%';
  progressBar.appendChild(progressFill);

  const timingLine = document.createElement('div');
  timingLine.style.fontFamily = 'var(--font-mono)';
  timingLine.style.fontSize = '0.7rem';
  timingLine.style.color = 'var(--text-muted)';
  timingLine.style.marginTop = '0.25rem';

  progressContainer.appendChild(progressLabel);
  progressContainer.appendChild(progressBar);
  progressContainer.appendChild(timingLine);

  const recoveredLine = document.createElement('div');
  recoveredLine.style.fontFamily = 'var(--font-mono)';
  recoveredLine.style.fontSize = '0.75rem';
  recoveredLine.style.color = 'var(--red-corrupt)';
  recoveredLine.style.marginTop = '0.75rem';
  recoveredLine.style.display = 'none';

  const predictionsHeader = document.createElement('div');
  predictionsHeader.style.fontFamily = 'var(--font-mono)';
  predictionsHeader.style.fontSize = '0.7rem';
  predictionsHeader.style.color = 'var(--text-secondary)';
  predictionsHeader.style.marginTop = '0.75rem';
  predictionsHeader.style.display = 'none';

  // Header row for predictions
  const predHeaderRow = document.createElement('div');
  predHeaderRow.className = 'prediction-row';
  predHeaderRow.style.fontWeight = '600';
  predHeaderRow.style.borderBottom = '2px solid var(--border-accent)';
  predHeaderRow.innerHTML = '<span>PREDICTED</span><span>ACTUAL</span><span>MATCH</span>';

  const predictionsList = document.createElement('div');

  const finalMessage = document.createElement('div');
  finalMessage.style.fontFamily = 'var(--font-mono)';
  finalMessage.style.fontSize = '0.8rem';
  finalMessage.style.color = 'var(--red-corrupt)';
  finalMessage.style.marginTop = '1rem';
  finalMessage.style.fontWeight = '600';
  finalMessage.style.display = 'none';
  finalMessage.textContent = '';

  // Filled in from the tallied match results once the predictions finish. The
  // headline used to be a fixed "All predictions matched" revealed by a row
  // count, so it read the same whether every row said \u2705 or every row said \u274c.
  const finalMessageInner = document.createElement('div');
  finalMessage.appendChild(finalMessageInner);

  // "Verify it yourself" callout shown after a successful attack.
  const nextClickEl = document.createElement('div');
  nextClickEl.style.cssText = 'font-family:var(--font-mono);font-size:0.78rem;line-height:1.6;margin-top:1rem;padding:0.75rem;border:1px solid var(--red-dim);background-color:rgba(255,0,0,0.04);display:none';

  theater.appendChild(statusLine);
  theater.appendChild(progressContainer);
  theater.appendChild(recoveredLine);
  theater.appendChild(predictionsHeader);
  theater.appendChild(predHeaderRow);
  theater.appendChild(predictionsList);
  theater.appendChild(finalMessage);
  theater.appendChild(nextClickEl);

  predHeaderRow.style.display = 'none';

  container.appendChild(theater);

  let predictionCount = 0;
  let matchCount = 0;
  let startTime = performance.now();
  let started = false;
  /** Candidates/sec measured during the search — reused in the summary. */
  let measuredRate = 0;
  let measuredElapsed = 0;
  /** How many intercepted blocks the search actually consumed. */
  let blocksUsed = 0;

  function fmtElapsed(ms: number): string {
    return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
  }

  /**
   * The closing verdict, written from the tally the rows above just produced.
   * Every number in it — how many predictions matched, how many blocks the
   * search consumed, how long it took — comes out of this run.
   */
  function renderSummary(): void {
    const allMatched = matchCount === predictionCount && predictionCount > 0;
    const headline = allMatched
      ? `TOTAL COMPROMISE — ${matchCount} of ${predictionCount} predictions matched.`
      : `PARTIAL — ${matchCount} of ${predictionCount} predictions matched. ` +
        'The recovered state does not reproduce this generator, so the attack did not fully succeed.';
    finalMessage.style.color = allMatched ? 'var(--red-corrupt)' : 'var(--amber-warn)';
    const body = allMatched
      ? `From ${blocksUsed} intercepted output blocks — ${blocksUsed * 240} bits of a stream the generator
         considered secret — the attacker recovered the full internal state and reproduced every subsequent
         output exactly. The search took ${fmtElapsed(measuredElapsed)} here, at
         ${measuredRate.toLocaleString()} candidates/sec in this tab. In a TLS session this means the attacker
         knows every session key, every nonce, every random value the server will ever use. The connection is
         completely transparent to them — and completely opaque to you.`
      : `The candidate that survived the search reproduces only ${matchCount} of ${predictionCount} subsequent
         outputs. That is not what a correct state recovery looks like: read the ❌ rows above against the
         ✅ ones, because this panel is reporting what the comparison actually returned rather than what the
         attack was supposed to do.`;
    finalMessageInner.innerHTML = `
      <p style="margin-bottom:0.5rem">${headline}</p>
      <p style="font-size:0.75rem;color:var(--text-secondary);font-weight:normal;line-height:1.6">${body}</p>
    `;
  }

  return {
    /** Show the two intercepted blocks and a picture of the 16-bit leak. */
    setIntercepted(hexA: string, hexB: string) {
      blocksUsed = 2;
      interceptedEl.style.display = 'block';
      interceptedEl.innerHTML = `
        <div style="color:var(--text-muted);margin-bottom:0.25rem">INTERCEPTED OUTPUT — two consecutive blocks you generated</div>
        <div><span style="color:var(--red-corrupt)">block 1</span>&nbsp; ${hexA}</div>
        <div><span style="color:var(--red-corrupt)">block 2</span>&nbsp; ${hexB}</div>
        <div style="margin-top:0.45rem;color:var(--text-secondary)">
          Each block is the low 240 bits of <em>r = (s·Q).x</em>. Only the top 16 bits were
          truncated, leaving just <strong style="color:var(--amber-warn)">2¹⁶ = 65,536</strong> possible points to test:
        </div>
        <div style="margin-top:0.35rem;display:flex;height:14px;border:1px solid var(--border-accent)">
          <div style="flex:240;background-color:var(--green-dim, rgba(0,255,128,0.25));"></div>
          <div style="flex:16;background-color:var(--amber-warn);"></div>
        </div>
        <div style="display:flex;margin-top:0.15rem;color:var(--text-muted);font-size:0.62rem">
          <div style="flex:240">240 bits known from output</div>
          <div style="flex:16;text-align:right;white-space:nowrap">16 unknown</div>
        </div>`;
    },
    /** Invite the learner to confirm the prediction with their own next click. */
    armNextClick(predictedHex: string) {
      nextClickEl.style.display = 'block';
      nextClickEl.innerHTML = `
        <div style="color:var(--red-corrupt);font-weight:600;margin-bottom:0.3rem">YOUR MOVE</div>
        The attacker now holds the generator's exact state. It predicts your <strong>next</strong>
        Generate click will output:
        <div style="color:var(--red-corrupt);margin:0.35rem 0;overflow-wrap:anywhere">${predictedHex}</div>
        <span style="color:var(--text-secondary)">Click <strong>Generate</strong> on the Dual_EC panel and watch your "random" output match it — before you clicked.</span>`;
    },
    handleEvent(event: AttackEvent) {
      switch (event.type) {
        case 'progress': {
          if (!started) { startTime = performance.now(); started = true; }
          const tried = event.candidatesTried ?? 0;
          const pct = (tried / event.totalCandidates * 100).toFixed(1);
          progressLabel.textContent = `Trying candidate [${tried.toLocaleString()} / ${event.totalCandidates.toLocaleString()}]...`;
          progressFill.style.width = `${pct}%`;
          progressBar.setAttribute('aria-valuenow', pct);
          const elapsed = performance.now() - startTime;
          const rate = elapsed > 0 ? Math.round((tried / elapsed) * 1000) : 0;
          measuredElapsed = elapsed;
          measuredRate = rate;
          timingLine.textContent = `${fmtElapsed(elapsed)} elapsed · ${rate.toLocaleString()} candidates/sec`;
          theater.classList.add('pulse-border');
          break;
        }
        case 'state_recovered': {
          progressFill.style.width = '100%';
          // The accessible value has to move with the bar. It used to be left on
          // whichever progress tick fired last (often "0.6", sometimes "0"),
          // so a screen-reader user was told the search was barely started
          // while the bar beside it rendered as complete.
          progressBar.setAttribute('aria-valuenow', '100');
          const elapsed = performance.now() - startTime;
          progressLabel.textContent = `Searched ${event.candidatesTried?.toLocaleString()} candidates in ${fmtElapsed(elapsed)}`;
          measuredElapsed = elapsed;
          if (elapsed > 0) {
            measuredRate = Math.round(((event.candidatesTried ?? 0) / elapsed) * 1000);
          }
          // The measured figures stay put. This slot used to be overwritten with
          // "Native code does this in well under a second" — an unmeasured
          // constant sitting where the run's own numbers had just been.
          timingLine.textContent =
            `State recovered from ${blocksUsed} intercepted output blocks in ${fmtElapsed(elapsed)}` +
            ` · ${measuredRate.toLocaleString()} candidates/sec in this browser tab.`;
          recoveredLine.style.display = 'block';
          const stateHex = event.recoveredState ?? '';
          const truncated = stateHex.length > 16 ? stateHex.substring(0, 16) + '...' : stateHex;
          recoveredLine.textContent = `STATE RECOVERED: s = 0x${truncated}`;
          statusLine.textContent = 'STATE RECOVERED';
          predictionsHeader.style.display = 'block';
          predictionsHeader.textContent = 'VERIFYING PREDICTIONS:';
          predHeaderRow.style.display = 'grid';
          break;
        }
        case 'prediction': {
          predictionCount++;
          const row = document.createElement('div');
          row.className = 'prediction-row';
          const predicted = event.predictedOutput ?? '';
          const truncPred = predicted.length > 20 ? predicted.substring(0, 20) + '...' : predicted;
          const actual = event.actualOutput ?? '(pending)';
          const truncActual = actual.length > 20 ? actual.substring(0, 20) + '...' : actual;
          // A row only counts as a match when the caller compared two real
          // strings and they were equal. An absent `match` is not a match.
          const matched = event.match === true;
          if (matched) {
            matchCount++;
          }
          row.innerHTML = `<span>${truncPred}</span><span>${truncActual}</span><span>${matched ? '✅' : '❌'}</span>`;
          predictionsList.appendChild(row);

          if (predictionCount >= 10) {
            renderSummary();
            finalMessage.style.display = 'block';
            theater.classList.remove('pulse-border');
          }
          break;
        }
      }
    },
    reset() {
      predictionCount = 0;
      matchCount = 0;
      blocksUsed = 0;
      measuredRate = 0;
      measuredElapsed = 0;
      finalMessageInner.innerHTML = '';
      started = false;
      timingLine.textContent = '';
      interceptedEl.style.display = 'none';
      nextClickEl.style.display = 'none';
      statusLine.textContent = 'INTERCEPTING OUTPUT BLOCKS...';
      progressLabel.textContent = '';
      progressFill.style.width = '0%';
      recoveredLine.style.display = 'none';
      predictionsHeader.style.display = 'none';
      predHeaderRow.style.display = 'none';
      predictionsList.innerHTML = '';
      finalMessage.style.display = 'none';
      theater.classList.remove('pulse-border');
    },
  };
}
