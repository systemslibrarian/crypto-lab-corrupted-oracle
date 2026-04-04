/**
 * Attack Theater — Live Backdoor Display
 *
 * Renders the Dual_EC_DRBG backdoor attack sequence with dramatic
 * visual effects: pulsing red borders, typewriter text, progress bar,
 * and prediction verification display.
 */

import type { AttackEvent } from '../types/drbg';

export function createAttackTheater(container: HTMLElement): {
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
      <li>The attack engine captured <strong>two consecutive 30-byte output blocks</strong> from Dual_EC_DRBG.</li>
      <li>The first block reveals 240 of 256 bits of the internal value <em>r</em>.
      The missing 16 bits mean 65,536 possible values.</li>
      <li>For each candidate, the engine computes what the <em>next</em> output block
      <strong>would</strong> be if that candidate were correct, using the secret
      scalar <em>d</em> = <em>e</em><sup>−1</sup>.</li>
      <li>When a candidate's predicted output matches the <em>actual</em> second block,
      the full internal state is recovered.</li>
    </ol>
    <p style="font-size:0.75rem;color:var(--text-muted)">
      After recovery, the engine predicts the next 10 outputs <em>before</em> they're generated
      — then generates them and compares. Every prediction should match exactly.
    </p>
  `;
  theater.appendChild(explainer);

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
  const progressFill = document.createElement('div');
  progressFill.className = 'progress-fill';
  progressFill.style.width = '0%';
  progressBar.appendChild(progressFill);

  progressContainer.appendChild(progressLabel);
  progressContainer.appendChild(progressBar);

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

  const finalMessageInner = document.createElement('div');
  finalMessageInner.innerHTML = `
    <p style="margin-bottom:0.5rem">TOTAL COMPROMISE \u2014 All predictions matched.</p>
    <p style="font-size:0.75rem;color:var(--text-secondary);font-weight:normal;line-height:1.6">
      From a single intercepted output, the attacker recovered the full internal state
      and now predicts every future output. In a TLS session, this means the attacker knows
      every session key, every nonce, every random value the server will ever use.
      The connection is completely transparent to them \u2014 and completely opaque to you.
    </p>
  `;
  finalMessage.appendChild(finalMessageInner);

  theater.appendChild(statusLine);
  theater.appendChild(progressContainer);
  theater.appendChild(recoveredLine);
  theater.appendChild(predictionsHeader);
  theater.appendChild(predHeaderRow);
  theater.appendChild(predictionsList);
  theater.appendChild(finalMessage);

  predHeaderRow.style.display = 'none';

  container.appendChild(theater);

  let predictionCount = 0;

  return {
    handleEvent(event: AttackEvent) {
      switch (event.type) {
        case 'progress': {
          const pct = ((event.candidatesTried ?? 0) / event.totalCandidates * 100).toFixed(1);
          progressLabel.textContent = `Trying candidate [${event.candidatesTried?.toLocaleString()} / ${event.totalCandidates.toLocaleString()}]...`;
          progressFill.style.width = `${pct}%`;
          theater.classList.add('pulse-border');
          break;
        }
        case 'state_recovered': {
          progressFill.style.width = '100%';
          progressLabel.textContent = `Exhausted ${event.candidatesTried?.toLocaleString()} candidates`;
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
          const matchIcon = event.match !== false ? '✅' : '❌';
          row.innerHTML = `<span>${truncPred}</span><span>${truncActual}</span><span>${matchIcon}</span>`;
          predictionsList.appendChild(row);

          if (predictionCount >= 10) {
            finalMessage.style.display = 'block';
            theater.classList.remove('pulse-border');
          }
          break;
        }
      }
    },
    reset() {
      predictionCount = 0;
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
