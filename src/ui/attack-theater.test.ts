// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from 'vitest';
import { createAttackTheater } from './attack-theater';
import type { AttackEvent } from '../types/drbg';

function prediction(match: boolean | undefined, i: number): AttackEvent {
  return {
    type: 'prediction',
    candidatesTried: 65536,
    totalCandidates: 65536,
    predictedOutput: `predicted-${i}`,
    actualOutput: match === true ? `predicted-${i}` : `actual-${i}`,
    match,
  } as AttackEvent;
}

describe('attack theater verdict', () => {
  let container: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = '';
    container = document.createElement('div');
    document.body.appendChild(container);
  });

  it('reports TOTAL COMPROMISE only when every prediction actually matched', () => {
    const theater = createAttackTheater(container);
    theater.setIntercepted('aa'.repeat(30), 'bb'.repeat(30));
    for (let i = 0; i < 10; i++) theater.handleEvent(prediction(true, i));
    const text = container.textContent ?? '';
    expect(text).toContain('TOTAL COMPROMISE');
    expect(text).toContain('10 of 10 predictions matched');
  });

  it('reports the measured tally when a prediction does not match', () => {
    // The headline used to be a fixed "All predictions matched" string revealed
    // once ten rows existed, so it read identically whether the comparisons had
    // succeeded or failed. It now comes out of the tally.
    const theater = createAttackTheater(container);
    theater.setIntercepted('aa'.repeat(30), 'bb'.repeat(30));
    for (let i = 0; i < 10; i++) theater.handleEvent(prediction(i !== 3, i));
    const text = container.textContent ?? '';
    expect(text).not.toContain('TOTAL COMPROMISE');
    expect(text).toContain('9 of 10 predictions matched');
    expect(text).toContain('did not fully succeed');
  });

  it('does not count a prediction with no comparison result as a match', () => {
    const theater = createAttackTheater(container);
    theater.setIntercepted('aa'.repeat(30), 'bb'.repeat(30));
    for (let i = 0; i < 10; i++) theater.handleEvent(prediction(undefined, i));
    const text = container.textContent ?? '';
    expect(text).toContain('0 of 10 predictions matched');
  });

  it('names two intercepted blocks, not one, and keeps the measured rate', () => {
    // Recovery needs two consecutive blocks: one leaves 2^16 candidates and the
    // second selects among them. The summary used to say "from a single
    // intercepted output" directly under a panel headed "two consecutive
    // blocks", and the timing slot was overwritten with an unmeasured constant.
    const theater = createAttackTheater(container);
    theater.setIntercepted('aa'.repeat(30), 'bb'.repeat(30));
    theater.handleEvent({
      type: 'progress',
      candidatesTried: 32768,
      totalCandidates: 65536,
    } as AttackEvent);
    theater.handleEvent({
      type: 'state_recovered',
      candidatesTried: 65536,
      totalCandidates: 65536,
      recoveredState: 'deadbeefdeadbeef00',
    } as AttackEvent);
    for (let i = 0; i < 10; i++) theater.handleEvent(prediction(true, i));
    const text = container.textContent ?? '';
    expect(text).not.toContain('single intercepted output');
    expect(text).toContain('2 intercepted output blocks');
    expect(text).not.toContain('well under a second');
    expect(text).toContain('candidates/sec');
  });

  it('clears the previous verdict on reset', () => {
    const theater = createAttackTheater(container);
    theater.setIntercepted('aa'.repeat(30), 'bb'.repeat(30));
    for (let i = 0; i < 10; i++) theater.handleEvent(prediction(true, i));
    expect(container.textContent).toContain('TOTAL COMPROMISE');
    theater.reset();
    expect(container.textContent).not.toContain('TOTAL COMPROMISE');
  });
});
