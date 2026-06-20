import { describe, it, expect } from 'vitest';
import { chacha20Block } from './chacha20-drbg';

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

describe('ChaCha20 block function', () => {
  it('matches the RFC 8439 §2.3.2 test vector', () => {
    // key = 00 01 02 ... 1f, nonce = 00:00:00:09 00:00:00:4a 00:00:00:00, counter = 1
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const nonce = new Uint8Array([
      0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ]);
    const expected =
      '10f1e7e4d13b5915500fdd1fa32071c4' +
      'c7d1f4c733c068030422aa9ac3d46c4e' +
      'd2826446079faa0914c2d705d98b02a2' +
      'b5129cd1de164eb9cbd083e8a2503c4e';
    expect(toHex(chacha20Block(key, 1, nonce))).toBe(expected);
  });

  it('rejects keys and nonces of the wrong length', () => {
    expect(() => chacha20Block(new Uint8Array(31), 0, new Uint8Array(12))).toThrow();
    expect(() => chacha20Block(new Uint8Array(32), 0, new Uint8Array(8))).toThrow();
  });
});
