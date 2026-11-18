// DER <-> r||s conversion, checked against node:crypto (OpenSSL) as an independent oracle.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { test } from 'node:test';
import { derSignatureToRaw, rawSignatureToDer } from '@identra/sdk-core';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

test('OpenSSL DER signatures convert to r||s that OpenSSL accepts, and back', () => {
  for (let i = 0; i < 50; i++) {
    const data = randomBytes(32);
    const der = new Uint8Array(sign('sha256', data, { key: privateKey, dsaEncoding: 'der' }));
    const raw = derSignatureToRaw(der);
    assert.equal(raw.length, 64);
    assert.ok(verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, raw));
    assert.deepEqual(rawSignatureToDer(raw), der);
  }
});

test('r||s with leading zero bytes and high bits round-trips through minimal DER', () => {
  const cases = [
    [0x00, 0x00, 0x7f],
    [0x80],
    [0x00, 0x80],
    [0xff],
    [0x00, 0x00, 0x00, 0x01],
  ];
  for (const prefix of cases) {
    const raw = new Uint8Array(randomBytes(64));
    raw.set(prefix, 0);
    raw.set(prefix, 32);
    const der = rawSignatureToDer(raw);
    assert.deepEqual(derSignatureToRaw(der), raw);
    assert.ok(der.length <= 72);
  }
});

test('malformed DER is rejected', () => {
  const r = [0x02, 0x01, 0x01];
  const bad: [string, number[]][] = [
    ['empty', []],
    ['not a SEQUENCE', [0x31, 0x06, ...r, ...r]],
    ['SEQUENCE length too long', [0x30, 0x07, ...r, ...r]],
    ['SEQUENCE length too short', [0x30, 0x05, ...r, ...r]],
    ['non-minimal long-form length', [0x30, 0x81, 0x06, ...r, ...r]],
    ['trailing byte', [0x30, 0x06, ...r, ...r, 0x00]],
    ['extra byte inside the SEQUENCE', [0x30, 0x07, ...r, ...r, 0x00]],
    ['only one INTEGER', [0x30, 0x03, ...r]],
    ['not an INTEGER', [0x30, 0x06, 0x04, 0x01, 0x01, ...r]],
    ['empty INTEGER', [0x30, 0x05, 0x02, 0x00, ...r]],
    ['negative INTEGER', [0x30, 0x06, 0x02, 0x01, 0x80, ...r]],
    ['non-minimal INTEGER', [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, ...r]],
    ['zero INTEGER', [0x30, 0x06, 0x02, 0x01, 0x00, ...r]],
    ['INTEGER of 33 value bytes', [0x30, 0x26, 0x02, 0x21, ...Array(33).fill(0x01), ...r]],
    ['truncated', [0x30, 0x06, ...r, 0x02, 0x01]],
  ];
  for (const [name, bytes] of bad) assert.throws(() => derSignatureToRaw(Uint8Array.from(bytes)), TypeError, name);
});

test('rawSignatureToDer rejects wrong lengths and zero values', () => {
  assert.throws(() => rawSignatureToDer(new Uint8Array(63)), TypeError);
  assert.throws(() => rawSignatureToDer(new Uint8Array(64)), TypeError);
});
