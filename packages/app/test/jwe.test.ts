// Compact JWE, ECDH-ES + A128GCM / A256GCM (RFC 7516, RFC 7518 section 4.6).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64UrlDecode, base64UrlEncode, hexDecode, utf8Decode, utf8Encode, type EcPublicJwk } from '@identra/sdk-core';
import { gcm } from '@noble/ciphers/aes.js';
import { p256 } from '@noble/curves/nist.js';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { createNobleSigner, decryptJwe, encryptJwe, generateSecretKey, JweError, MAX_JWE_LENGTH, type JweEnc } from '@identra/sdk-app';
import { countingRandom, queuedRandom, seededRandom } from './helpers/random.js';

const ENCS: JweEnc[] = ['A128GCM', 'A256GCM'];
const toBytes = (v: bigint, len: number): Uint8Array => hexDecode(v.toString(16).padStart(len * 2, '0'));

function recipient() {
  const secretKey = generateSecretKey(countingRandom());
  return { secretKey, publicJwk: createNobleSigner(secretKey).publicJwk };
}
const privateJwk = (k: { secretKey: Uint8Array; publicJwk: EcPublicJwk }) => ({ ...k.publicJwk, d: base64UrlEncode(k.secretKey) });

const jweCode = (code: JweError['code']) => (e: unknown) => e instanceof JweError && e.code === code;

function headerOf(jwe: string): Record<string, unknown> {
  return JSON.parse(utf8Decode(base64UrlDecode(jwe.split('.')[0]!)));
}
function withHeader(jwe: string, header: Record<string, unknown>): string {
  const parts = jwe.split('.');
  parts[0] = base64UrlEncode(utf8Encode(JSON.stringify(header)));
  return parts.join('.');
}
function flipPart(jwe: string, index: number, byte = 0): string {
  const parts = jwe.split('.');
  const b = base64UrlDecode(parts[index]!);
  b[byte]! ^= 0x01;
  parts[index] = base64UrlEncode(b);
  return parts.join('.');
}

describe('interop with jose', () => {
  for (const enc of ENCS) {
    for (const party of [undefined, { apu: 'wallet-nonce', apv: 'request-nonce' }]) {
      const label = `${enc}${party ? ' with apu/apv' : ''}`;

      test(`encryptJwe -> jose compactDecrypt (${label})`, async () => {
        const r = recipient();
        const header = { kid: 'enc-1', typ: 'oauth-authz-req+jwt', cty: 'json', ...(party ? { apu: base64UrlEncode(utf8Encode(party.apu)), apv: base64UrlEncode(utf8Encode(party.apv)) } : {}) };
        const jwe = encryptJwe({ recipientPublicJwk: r.publicJwk, enc, plaintext: utf8Encode('{"hello":"jose"}'), random: countingRandom(), header });
        const out = await compactDecrypt(jwe, await importJWK(privateJwk(r), 'ECDH-ES'));
        assert.equal(utf8Decode(out.plaintext), '{"hello":"jose"}');
        assert.equal(out.protectedHeader.alg, 'ECDH-ES');
        assert.equal(out.protectedHeader.enc, enc);
        assert.equal(out.protectedHeader.kid, 'enc-1');
        assert.equal(out.protectedHeader.apu, header.apu);
        assert.equal(out.protectedHeader.apv, header.apv);
      });

      test(`jose CompactEncrypt -> decryptJwe (${label})`, async () => {
        const r = recipient();
        const e = new CompactEncrypt(utf8Encode('{"hello":"noble"}')).setProtectedHeader({ alg: 'ECDH-ES', enc, kid: 'w-1' });
        if (party) e.setKeyManagementParameters({ apu: utf8Encode(party.apu), apv: utf8Encode(party.apv) });
        const jwe = await e.encrypt(await importJWK(r.publicJwk, 'ECDH-ES'));
        const out = decryptJwe({ jwe, recipientSecretKey: r.secretKey });
        assert.equal(utf8Decode(out.plaintext), '{"hello":"noble"}');
        assert.equal(out.header.enc, enc);
        assert.equal(out.header.kid, 'w-1');
        assert.equal(out.header.apu, party ? base64UrlEncode(utf8Encode(party.apu)) : undefined);
      });
    }
  }
});

describe('RFC 7518 Appendix C (ECDH-ES direct, A128GCM, apu "Alice", apv "Bob")', () => {
  // Values copied from https://www.rfc-editor.org/rfc/rfc7518.txt, Appendix C.
  const ALICE = { x: 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0', y: 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps', d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo' };
  const BOB = { x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ', y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck', d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw' };
  const DERIVED_KEY = 'VqqN6vgjbSBcIijNcacQGg';

  test('Alice ephemeral -> Bob: the content key is the RFC derived key', () => {
    // generateSecretKey maps a 48-byte seed to (seed mod (n - 1)) + 1, so seed = d - 1 yields d.
    const aliceD = BigInt('0x' + Array.from(base64UrlDecode(ALICE.d), (b) => b.toString(16).padStart(2, '0')).join(''));
    const iv = new Uint8Array(12).fill(9);
    const jwe = encryptJwe({
      recipientPublicJwk: { kty: 'EC', crv: 'P-256', x: BOB.x, y: BOB.y },
      enc: 'A128GCM',
      plaintext: utf8Encode('Live long and prosper.'),
      random: queuedRandom(toBytes(aliceD - 1n, 48), iv),
      header: { apu: 'QWxpY2U', apv: 'Qm9i' },
    });
    const parts = jwe.split('.');
    assert.deepEqual(headerOf(jwe), { alg: 'ECDH-ES', enc: 'A128GCM', epk: { kty: 'EC', crv: 'P-256', x: ALICE.x, y: ALICE.y }, apu: 'QWxpY2U', apv: 'Qm9i' });
    assert.equal(parts[1], '');
    assert.equal(parts[2], base64UrlEncode(iv));
    // Open it with the RFC's derived key directly: proves the Concat KDF output.
    const opened = gcm(base64UrlDecode(DERIVED_KEY), iv, utf8Encode(parts[0]!)).decrypt(new Uint8Array([...base64UrlDecode(parts[3]!), ...base64UrlDecode(parts[4]!)]));
    assert.equal(utf8Decode(opened), 'Live long and prosper.');
    assert.equal(utf8Decode(decryptJwe({ jwe, recipientSecretKey: base64UrlDecode(BOB.d) }).plaintext), 'Live long and prosper.');
  });
});

describe('randomness', () => {
  test('the ephemeral key (48 bytes) and IV (12 bytes) come only from the injected RandomSource', (t) => {
    const r = recipient();
    const spy = t.mock.method(globalThis.crypto, 'getRandomValues');
    const random = countingRandom(seededRandom(7));
    const a = encryptJwe({ recipientPublicJwk: r.publicJwk, enc: 'A256GCM', plaintext: utf8Encode('x'), random });
    const b = encryptJwe({ recipientPublicJwk: r.publicJwk, enc: 'A256GCM', plaintext: utf8Encode('x'), random });
    assert.deepEqual(random.calls, [48, 12, 48, 12]);
    assert.equal(spy.mock.callCount(), 0);
    assert.notDeepEqual(headerOf(a)['epk'], headerOf(b)['epk']);
    assert.notEqual(a.split('.')[2], b.split('.')[2]);
    // Same source state, same output: nothing else feeds in.
    assert.equal(encryptJwe({ recipientPublicJwk: r.publicJwk, enc: 'A256GCM', plaintext: utf8Encode('x'), random: seededRandom(7) }), a);
  });
});

describe('decryptJwe rejects', () => {
  const r = recipient();
  const good = encryptJwe({ recipientPublicJwk: r.publicJwk, enc: 'A128GCM', plaintext: utf8Encode('secret payload'), random: countingRandom(), header: { kid: 'k' } });
  const open = (jwe: string, key = r.secretKey) => decryptJwe({ jwe, recipientSecretKey: key });

  test('the untouched JWE decrypts', () => {
    assert.equal(utf8Decode(open(good).plaintext), 'secret payload');
  });

  test('tampering with each of the five parts', () => {
    assert.throws(() => open(withHeader(good, { ...headerOf(good), kid: 'other' })), jweCode('JWE_DECRYPTION_FAILED'));
    assert.throws(() => open(good.replace('..', '.AAAA.')), jweCode('JWE_INVALID'));
    assert.throws(() => open(flipPart(good, 2)), jweCode('JWE_DECRYPTION_FAILED'));
    assert.throws(() => open(flipPart(good, 3)), jweCode('JWE_DECRYPTION_FAILED'));
    assert.throws(() => open(flipPart(good, 4, 15)), jweCode('JWE_DECRYPTION_FAILED'));
  });

  test('the wrong key', () => {
    assert.throws(() => open(good, recipient().secretKey), jweCode('JWE_DECRYPTION_FAILED'));
  });

  test('a failure message carries no detail', () => {
    for (const jwe of [flipPart(good, 3), good.slice(1)]) {
      try {
        open(jwe);
        assert.fail('decrypted');
      } catch (e) {
        assert.ok(e instanceof JweError);
        assert.ok(['invalid JWE', 'JWE decryption failed'].includes(e.message));
        assert.equal(e.cause, undefined);
      }
    }
  });

  test('an invalid-curve epk (other curve, off-curve, identity, compressed, P-384, private) before any ECDH', () => {
    const epk = headerOf(good)['epk'] as EcPublicJwk;
    // A point on y^2 = x^3 - 3x + b' over the P-256 field, b' != b: the classic invalid-curve point.
    const { Fp } = p256.Point;
    const x = 5n;
    const y = 7n;
    assert.notEqual(Fp.create(y * y - (x * x * x - 3n * x)), p256.Point.CURVE().b);
    const otherCurve = { kty: 'EC', crv: 'P-256', x: base64UrlEncode(toBytes(x, 32)), y: base64UrlEncode(toBytes(y, 32)) };
    const yFlipped = base64UrlDecode(epk.y);
    yFlipped[31]! ^= 1;
    const zero = base64UrlEncode(new Uint8Array(32));
    const p384 = { kty: 'EC', crv: 'P-384', x: base64UrlEncode(new Uint8Array(48).fill(1)), y: base64UrlEncode(new Uint8Array(48).fill(2)) };
    const compressed = { ...epk, x: base64UrlEncode(new Uint8Array([2, ...base64UrlDecode(epk.x)])) };
    const bad = [otherCurve, { ...epk, y: base64UrlEncode(yFlipped) }, { ...epk, x: zero, y: zero }, compressed, p384, { ...epk, d: base64UrlEncode(r.secretKey) }, { ...epk, kty: 'OKP' }, 'epk', null];
    // JWE_INVALID is raised by header parsing, which runs before the key agreement; a failed
    // agreement or tag would be JWE_DECRYPTION_FAILED.
    for (const e of bad) assert.throws(() => open(withHeader(good, { ...headerOf(good), epk: e })), jweCode('JWE_INVALID'), JSON.stringify(e));
    const noEpk = headerOf(good);
    delete noEpk['epk'];
    assert.throws(() => open(withHeader(good, noEpk)), jweCode('JWE_INVALID'));
  });

  test('zip, crit, other alg / enc, unknown members, a non-empty encrypted key', () => {
    const h = headerOf(good);
    const headers: Record<string, unknown>[] = [
      { ...h, zip: 'DEF' },
      { ...h, crit: ['exp'], exp: 1 },
      { ...h, crit: [] },
      { ...h, alg: 'RSA-OAEP' },
      { ...h, alg: 'ECDH-ES+A128KW' },
      { ...h, alg: 'dir' },
      { ...h, enc: 'A128CBC-HS256' },
      { ...h, enc: 'A192GCM' },
      { ...h, foo: 'bar' },
      { ...h, kid: 7 },
      { ...h, apu: 'not base64url!' },
    ];
    for (const header of headers) assert.throws(() => open(withHeader(good, header)), jweCode('JWE_INVALID'), JSON.stringify(header));
    const parts = good.split('.');
    parts[1] = base64UrlEncode(new Uint8Array(16));
    assert.throws(() => open(parts.join('.')), jweCode('JWE_INVALID'));
  });

  test('wrong structure, sizes and encodings', () => {
    const parts = good.split('.');
    const cases = [
      parts.slice(0, 4).join('.'),
      [...parts, ''].join('.'),
      good + '=',
      [parts[0], '', base64UrlEncode(new Uint8Array(16)), parts[3], parts[4]].join('.'),
      [parts[0], '', parts[2], parts[3], base64UrlEncode(new Uint8Array(12))].join('.'),
      [base64UrlEncode(utf8Encode('[1]')), '', parts[2], parts[3], parts[4]].join('.'),
      [base64UrlEncode(new Uint8Array([0xff, 0xfe])), '', parts[2], parts[3], parts[4]].join('.'),
      '',
      'a'.repeat(MAX_JWE_LENGTH + 1),
    ];
    for (const jwe of cases) assert.throws(() => open(jwe), jweCode('JWE_INVALID'), jwe.slice(0, 40));
    assert.throws(() => decryptJwe({ jwe: 42 as unknown as string, recipientSecretKey: r.secretKey }), jweCode('JWE_INVALID'));
    assert.throws(() => decryptJwe({ jwe: good, recipientSecretKey: new Uint8Array(32) }), TypeError);
  });

  test('an all-zero shared secret (a P-256 point with x = 0) in both directions', () => {
    // y^2 = b has a root mod p, so (0, sqrt(b)) is on P-256. With epk = d^-1 * P0 the recipient's
    // agreement d * epk = P0 has x = 0, i.e. Z is 32 zero bytes.
    const P0 = p256.Point.fromAffine({ x: 0n, y: p256.Point.Fp.sqrt(p256.Point.CURVE().b) });
    P0.assertValidity();
    const d = BigInt('0x' + Array.from(r.secretKey, (b) => b.toString(16).padStart(2, '0')).join(''));
    const epkPoint = P0.multiply(p256.Point.Fn.inv(d)).toBytes(false);
    const epk = { kty: 'EC', crv: 'P-256', x: base64UrlEncode(epkPoint.subarray(1, 33)), y: base64UrlEncode(epkPoint.subarray(33)) };
    assert.throws(() => open(withHeader(good, { ...headerOf(good), epk })), jweCode('JWE_DECRYPTION_FAILED'));
    // Sender side: recipient P0 and an all-zero seed (ephemeral scalar 1) give Z = 0 too.
    const p0Bytes = P0.toBytes(false);
    const p0Jwk: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: base64UrlEncode(p0Bytes.subarray(1, 33)), y: base64UrlEncode(p0Bytes.subarray(33)) };
    assert.throws(
      () => encryptJwe({ recipientPublicJwk: p0Jwk, enc: 'A128GCM', plaintext: new Uint8Array(1), random: queuedRandom(new Uint8Array(48), new Uint8Array(12)) }),
      jweCode('JWE_DECRYPTION_FAILED'),
    );
  });
});

describe('encryptJwe programmer errors', () => {
  const r = recipient();
  test('bad recipient key, enc, plaintext or header members', () => {
    const base = { recipientPublicJwk: r.publicJwk, enc: 'A128GCM' as JweEnc, plaintext: new Uint8Array(1), random: countingRandom() };
    const y = base64UrlDecode(r.publicJwk.y);
    y[3]! ^= 1;
    assert.throws(() => encryptJwe({ ...base, recipientPublicJwk: { ...r.publicJwk, y: base64UrlEncode(y) } }), TypeError);
    assert.throws(() => encryptJwe({ ...base, enc: 'A128CBC-HS256' as JweEnc }), TypeError);
    assert.throws(() => encryptJwe({ ...base, plaintext: 'text' as unknown as Uint8Array }), TypeError);
    assert.throws(() => encryptJwe({ ...base, header: { apu: 'Alice!' } }), TypeError);
    assert.throws(() => encryptJwe({ ...base, header: { kid: 1 as unknown as string } }), TypeError);
  });
});
