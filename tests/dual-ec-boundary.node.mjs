import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { stripTypeScriptTypes } from 'node:module';

// Exercise the actual TypeScript module without a second handwritten generator
// or a shipped test/debug API. Only erase types and resolve its existing import.
const scratch = mkdtempSync(join(tmpdir(), 'dual-ec-boundary-'));
after(() => rmSync(scratch, { recursive: true }));
for (const file of ['types/drbg', 'algorithms/dual-ec-drbg']) {
  const source = readFileSync(new URL(`../src/${file}.ts`, import.meta.url), 'utf8');
  const compiled = stripTypeScriptTypes(source)
    .replaceAll('../types/drbg\'', '../types/drbg.mjs\'');
  mkdirSync(join(scratch, file.split('/')[0]), { recursive: true });
  writeFileSync(join(scratch, `${file}.mjs`), compiled);
}
const lab = await import(pathToFileURL(join(scratch, 'algorithms/dual-ec-drbg.mjs')));

// Independent EC oracle: Node/OpenSSL prime256v1, not the lab's group arithmetic,
// attacker, curve constants or scalar-multiplication implementation.
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const e = 0xdeadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdefn;
const bytes = s => Buffer.from(s.toString(16).padStart(64, '0'), 'hex');
const scalar = b => BigInt(`0x${Buffer.from(b).toString('hex')}`);
const empty = new Uint8Array();
function point(s) {
  const ec = createECDH('prime256v1');
  ec.setPrivateKey(bytes(s % order));
  return ec.getPublicKey(undefined, 'uncompressed');
}
const x = s => scalar(point(s).subarray(1, 33));
function round(s) {
  const nextState = x(s);
  // Q = eG implies sQ = (s*e mod n)G, independently evaluated by OpenSSL.
  return { nextState, output: point(nextState * e).subarray(3, 33) };
}
function state(s, counter = 1) {
  return {
    algorithm: 'Dual-EC-DRBG', instantiated: true, securityStrength: 256,
    reseedCounter: counter, internalState: new Uint8Array(bytes(s)),
  };
}

test('the real demo P and Q equal independent OpenSSL curve points', () => {
  const p = point(1n), q = point(e);
  assert.equal(lab.NIST_P.x, scalar(p.subarray(1, 33)));
  assert.equal(lab.NIST_P.y, scalar(p.subarray(33)));
  assert.equal(lab.DEMO_Q.x, scalar(q.subarray(1, 33)));
  assert.equal(lab.DEMO_Q.y, scalar(q.subarray(33)));
});

test('a 240-bit model request keeps the output-round state, omitting NIST step 14', async () => {
  const expected = round(12345n);
  const finalNistState = x(expected.nextState);
  // Independently reproduce the report's specific scalar-state counterexample.
  assert.equal(expected.nextState.toString(16), '26efcebd0ee9e34a669187e18b3a9122b2f733945b649cc9f9f921e9f9dad812');
  assert.equal(finalNistState.toString(16), '9c51a4089ffcbd3690841fc97952f50ddfe9ebbd54aafaf21ea318808bf033c7');
  const actual = await lab.dualEcDrbgGenerate(state(12345n), 240, empty);
  assert.deepEqual(Buffer.from(actual.result.bytes), expected.output);
  assert.equal(scalar(actual.state.internalState), expected.nextState);
  assert.notEqual(scalar(actual.state.internalState), finalNistState);
});

test('the next separate model request differs from the NIST request-boundary recurrence', async () => {
  const first = round(12345n);
  const modelSecond = round(first.nextState);
  const nistSecond = round(x(first.nextState));
  const actualFirst = await lab.dualEcDrbgGenerate(state(12345n), 240, empty);
  const actualSecond = await lab.dualEcDrbgGenerate(actualFirst.state, 240, empty);
  assert.deepEqual(Buffer.from(actualSecond.result.bytes), modelSecond.output);
  assert.notDeepEqual(Buffer.from(actualSecond.result.bytes), nistSecond.output);
});

test('two blocks in one request use one model-counter increment, unlike NIST step 10', async () => {
  const first = round(12345n), second = round(first.nextState);
  const together = await lab.dualEcDrbgGenerate(state(12345n), 480, empty);
  assert.deepEqual(Buffer.from(together.result.bytes), Buffer.concat([first.output, second.output]));
  assert.equal(scalar(together.state.internalState), second.nextState);
  assert.notEqual(scalar(together.state.internalState), x(second.nextState));
  assert.equal(together.state.reseedCounter, 2); // starts at 1, counts requests
  const a = await lab.dualEcDrbgGenerate(state(12345n), 240, empty);
  const b = await lab.dualEcDrbgGenerate(a.state, 240, empty);
  assert.equal(b.state.reseedCounter, 3);
  assert.deepEqual(Buffer.from(b.state.internalState), Buffer.from(together.state.internalState));
});

test('model instantiation ignores nonce/personalization and always uses P-256', async () => {
  const entropy = new Uint8Array([1, 2, 3, 4]);
  const hash = createHash('sha256').update(entropy).digest();
  const expected = scalar(hash) % (order - 1n) + 1n;
  for (const strength of [128, 192, 256]) {
    const a = await lab.dualEcDrbgInstantiate(entropy, empty, empty, strength);
    const b = await lab.dualEcDrbgInstantiate(entropy, new Uint8Array([9]), new Uint8Array([8]), strength);
    assert.equal(scalar(a.internalState), expected);
    assert.deepEqual(a, b);
    assert.equal(a.reseedCounter, 1);
  }
});

test('model reseeding uses scalar addition and ignores additional input', async () => {
  const entropy = new Uint8Array([5, 6, 7]);
  const expected = (12345n + scalar(createHash('sha256').update(entropy).digest())) % (order - 1n) + 1n;
  const a = await lab.dualEcDrbgReseed(state(12345n, 7), entropy, empty);
  const b = await lab.dualEcDrbgReseed(state(12345n, 7), entropy, new Uint8Array([9]));
  assert.equal(scalar(a.internalState), expected);
  assert.deepEqual(a, b);
  assert.equal(a.reseedCounter, 1);
});

test('model generation ignores additional input and does not enforce a reseed interval', async () => {
  const a = await lab.dualEcDrbgGenerate(state(12345n, 2 ** 48), 240, empty);
  const b = await lab.dualEcDrbgGenerate(state(12345n, 2 ** 48), 240, new Uint8Array([9]));
  assert.deepEqual(a, b);
  assert.equal(a.result.reseedRequired, false);
});
