// Byte encodings, checked against Node's Buffer as an independent oracle.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
  utf8Decode,
  utf8Encode,
} from '@identra/sdk-core';

test('round trips match Buffer for every length 0..64', () => {
  for (let n = 0; n <= 64; n++) {
    const b = new Uint8Array(randomBytes(n));
    assert.equal(base64UrlEncode(b), Buffer.from(b).toString('base64url'));
    assert.equal(base64Encode(b), Buffer.from(b).toString('base64'));
    assert.equal(hexEncode(b), Buffer.from(b).toString('hex'));
    assert.deepEqual(base64UrlDecode(base64UrlEncode(b)), b);
    assert.deepEqual(base64Decode(base64Encode(b)), b);
    assert.deepEqual(hexDecode(hexEncode(b)), b);
  }
});

test('base64url decoding is strict', () => {
  for (const bad of ['A', 'AA==', 'AB', 'A+', 'A/', 'AA AA', 'AAA\n', 'Zg=']) {
    assert.throws(() => base64UrlDecode(bad), TypeError, bad);
  }
  assert.deepEqual(base64UrlDecode('Zg'), utf8Encode('f'));
  assert.deepEqual(base64UrlDecode('-_8'), Uint8Array.from([0xfb, 0xff]));
});

test('standard base64 decoding is strict', () => {
  for (const bad of ['Zg', 'Zg=', 'Zh==', 'Zm9=', '-_8=', 'Zm9v\n', ' Zm9v', 'Z===', '=Zg=', 'Zg==Zg==']) {
    assert.throws(() => base64Decode(bad), TypeError, bad);
  }
  assert.deepEqual(base64Decode('Zg=='), utf8Encode('f'));
  assert.deepEqual(base64Decode('Zm8='), utf8Encode('fo'));
  assert.deepEqual(base64Decode('Zm9v'), utf8Encode('foo'));
});

test('UTF-8 matches TextEncoder / TextDecoder and rejects invalid input', () => {
  for (const s of ['', 'ascii', 'Trường Mẫu', '€', '𝄞 emoji 😀', '\u0000']) {
    assert.deepEqual(utf8Encode(s), new TextEncoder().encode(s));
    assert.equal(utf8Decode(new TextEncoder().encode(s)), s);
  }
  const invalid = [[0x80], [0xc0, 0x80], [0xc3], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xff]];
  for (const b of invalid) assert.throws(() => utf8Decode(Uint8Array.from(b)), TypeError, String(b));
  assert.throws(() => utf8Encode('\ud800'), TypeError);
  assert.throws(() => utf8Encode('\udc00x'), TypeError);
});

test('hex decoding is strict', () => {
  for (const bad of ['a', 'zz', '0x00', ' 00']) assert.throws(() => hexDecode(bad), TypeError, bad);
  assert.deepEqual(hexDecode('00Ff'), Uint8Array.from([0, 255]));
});
