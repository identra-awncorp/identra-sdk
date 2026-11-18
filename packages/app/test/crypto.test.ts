// The @noble ES256 adapters (docs/architecture.md section 2 and 6, ADR-0006, ADR-0004 "Bổ sung
// 2026-11-19" point 2).
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { describe, test } from 'node:test';
import {
  base64UrlDecode,
  base64UrlEncode,
  decodeJws,
  derSignatureToRaw,
  hexDecode,
  rawSignatureToDer,
  signJws,
  utf8Encode,
  verifyJwsSignature,
  type EcPublicJwk,
  type Signer,
  type Verifier,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { p256, p384 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createDerSigningAdapter, createNobleSigner, generateSecretKey, nobleHasher, nobleVerifier } from '@identra/sdk-app';
import { P256 } from '../dist/crypto/noble.js';
import { constantRandom, countingRandom, seededRandom } from './helpers/random.js';

const N = p256.Point.CURVE().n;
const HALF_N = N >> 1n;
const toBytes32 = (v: bigint): Uint8Array => hexDecode(v.toString(16).padStart(64, '0'));
const toBig = (b: Uint8Array): bigint => BigInt('0x' + (Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('') || '0'));
const rs = (r: bigint, s: bigint): Uint8Array => {
  const out = new Uint8Array(64);
  out.set(toBytes32(r), 0);
  out.set(toBytes32(s), 32);
  return out;
};
const DATA = utf8Encode('eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ');

// RFC 7515 Appendix A.3. Copied from packages/core/test/jws.test.ts (the vector is not exported
// from a helper there), which extracted it from https://www.rfc-editor.org/rfc/rfc7515.txt.
const RFC7515_A3 = {
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
  jws: 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
};
const RFC7515_PUBLIC: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: RFC7515_A3.x, y: RFC7515_A3.y };

// RFC 6979 Appendix A.2.5 (P-256), SHA-256, from https://www.rfc-editor.org/rfc/rfc6979.txt.
const RFC6979 = {
  x: 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
  Ux: '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
  Uy: '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
  sample: {
    r: 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
    s: 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8',
  },
  test: {
    r: 'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
    s: '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083',
  },
};

describe('P-256 instance', () => {
  test('the hand-copied domain parameters equal noble p256', () => {
    assert.deepEqual(P256.Point.CURVE(), p256.Point.CURVE());
    assert.equal(P256.lengths.seed, 48);
  });
});

describe('nobleVerifier', () => {
  test('RFC 7515 A.3 verifies; a one-byte change of input or signature fails', async () => {
    const r = decodeJws(RFC7515_A3.jws);
    assert.ok(r.ok);
    assert.equal(await verifyJwsSignature(r.jws, RFC7515_PUBLIC, nobleVerifier), true);
    const flipped = (b: Uint8Array, i: number) => {
      const c = b.slice();
      c[i]! ^= 1;
      return c;
    };
    assert.equal(await nobleVerifier.verify(RFC7515_PUBLIC, flipped(r.jws.signingInput, 5), r.jws.signature), false);
    assert.equal(await nobleVerifier.verify(RFC7515_PUBLIC, r.jws.signingInput, flipped(r.jws.signature, 40)), false);
  });

  test('cross-backend: noble signs, WebCrypto verifies, and the reverse', async () => {
    const noble = createNobleSigner(generateSecretKey(countingRandom()));
    const fresh = await generateWebCryptoKeyPair();
    const web = await createWebCryptoSigner({ privateKey: fresh.privateKey });
    const pairs: [Signer, Verifier][] = [
      [noble, webCryptoVerifier],
      [web, nobleVerifier],
      [noble, nobleVerifier],
    ];
    for (const [signer, verifier] of pairs) {
      const compact = await signJws({ typ: 'JWT' }, utf8Encode('{"iss":"https://example.test"}'), signer);
      const r = decodeJws(compact);
      assert.ok(r.ok);
      assert.equal(await verifyJwsSignature(r.jws, signer.publicJwk, verifier), true);
    }
  });

  test('accepts high-S, like WebCrypto', async () => {
    const signer = createNobleSigner(generateSecretKey(countingRandom()));
    const low = await signer.sign(DATA);
    const high = rs(toBig(low.subarray(0, 32)), N - toBig(low.subarray(32)));
    assert.ok(toBig(high.subarray(32)) > HALF_N);
    assert.equal(await nobleVerifier.verify(signer.publicJwk, DATA, high), true);
    assert.equal(await webCryptoVerifier.verify(signer.publicJwk, DATA, high), true);
  });

  test('r or s equal to 0, n-1, n, n+1 (or 2^256-1) is rejected', async () => {
    const signer = createNobleSigner(generateSecretKey(countingRandom()));
    const good = await signer.sign(DATA);
    const r = toBig(good.subarray(0, 32));
    const s = toBig(good.subarray(32));
    for (const bad of [0n, N - 1n, N, N + 1n, 2n ** 256n - 1n]) {
      assert.equal(await nobleVerifier.verify(signer.publicJwk, DATA, rs(bad, s)), false, `r = ${bad}`);
      assert.equal(await nobleVerifier.verify(signer.publicJwk, DATA, rs(r, bad)), false, `s = ${bad}`);
    }
  });

  test('rejects off-curve, compressed, identity, other-curve and private JWKs', async () => {
    const signer = createNobleSigner(generateSecretKey(countingRandom()));
    const sig = await signer.sign(DATA);
    const pub = signer.publicJwk;
    const y = base64UrlDecode(pub.y);
    y[31]! ^= 1;
    const k1 = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), false);
    const p384Point = p384.getPublicKey(p384.utils.randomSecretKey(), false);
    const zero = base64UrlEncode(new Uint8Array(32));
    const bad: unknown[] = [
      { ...pub, y: base64UrlEncode(y) },
      { ...pub, x: base64UrlEncode(p256.Point.fromBytes(new Uint8Array([4, ...base64UrlDecode(pub.x), ...base64UrlDecode(pub.y)])).toBytes(true)) },
      { ...pub, x: zero, y: zero },
      { kty: 'EC', crv: 'secp256k1', x: base64UrlEncode(k1.subarray(1, 33)), y: base64UrlEncode(k1.subarray(33)) },
      { kty: 'EC', crv: 'P-256', x: base64UrlEncode(k1.subarray(1, 33)), y: base64UrlEncode(k1.subarray(33)) },
      { kty: 'EC', crv: 'P-384', x: base64UrlEncode(p384Point.subarray(1, 49)), y: base64UrlEncode(p384Point.subarray(49)) },
      { ...pub, d: base64UrlEncode(new Uint8Array(32)) },
      { kty: 'OKP', crv: 'Ed25519', x: pub.x },
      null,
      'not a jwk',
      [pub.x, pub.y],
    ];
    assert.equal(await nobleVerifier.verify(pub, DATA, sig), true);
    for (const jwk of bad) assert.equal(await nobleVerifier.verify(jwk as EcPublicJwk, DATA, sig), false, JSON.stringify(jwk));
  });

  test('returns false, never throws: throwing getters, proxies, wrong argument types, DER signatures', async () => {
    const signer = createNobleSigner(generateSecretKey(countingRandom()));
    const sig = await signer.sign(DATA);
    const getter = Object.defineProperty({ kty: 'EC', crv: 'P-256', y: signer.publicJwk.y }, 'x', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    const proxy = new Proxy(
      {},
      {
        has() {
          throw new Error('boom');
        },
        get() {
          throw new Error('boom');
        },
      },
    );
    for (const jwk of [getter, proxy]) assert.equal(await nobleVerifier.verify(jwk as EcPublicJwk, DATA, sig), false);
    const asAny = nobleVerifier.verify as (...a: unknown[]) => Promise<boolean>;
    assert.equal(await asAny(signer.publicJwk, 'string data', sig), false);
    assert.equal(await asAny(signer.publicJwk, DATA, Array.from(sig)), false);
    assert.equal(await asAny(signer.publicJwk, DATA, sig.subarray(0, 63)), false);
    assert.equal(await asAny(signer.publicJwk, DATA, new Uint8Array([...sig, 0])), false);
    assert.equal(await asAny(signer.publicJwk, DATA, rawSignatureToDer(sig)), false);
  });
});

describe('createNobleSigner', () => {
  test('RFC 6979 A.2.5 (P-256, SHA-256): public key, r, and s in its low-S form', async () => {
    const signer = createNobleSigner(hexDecode(RFC6979.x));
    assert.deepEqual(base64UrlDecode(signer.publicJwk.x), hexDecode(RFC6979.Ux));
    assert.deepEqual(base64UrlDecode(signer.publicJwk.y), hexDecode(RFC6979.Uy));
    const sample = await signer.sign(utf8Encode('sample'));
    // The RFC value of s is high; the adapter returns n - s.
    assert.ok(BigInt('0x' + RFC6979.sample.s) > HALF_N);
    assert.deepEqual(sample, rs(BigInt('0x' + RFC6979.sample.r), N - BigInt('0x' + RFC6979.sample.s)));
    assert.deepEqual(await signer.sign(utf8Encode('test')), rs(BigInt('0x' + RFC6979.test.r), BigInt('0x' + RFC6979.test.s)));
  });

  test('RFC 7515 A.3 key: public JWK derived from d, no x5c, kid only when given', async () => {
    const signer = createNobleSigner(base64UrlDecode(RFC7515_A3.d));
    assert.deepEqual(signer.publicJwk, RFC7515_PUBLIC);
    assert.equal(signer.alg, 'ES256');
    assert.equal('x5c' in signer, false);
    assert.equal('kid' in signer, false);
    assert.equal(createNobleSigner(base64UrlDecode(RFC7515_A3.d), { kid: 'k1' }).kid, 'k1');
  });

  test('output is always 64-byte low-S r||s that verifies on both backends', async () => {
    const signer = createNobleSigner(generateSecretKey(countingRandom()));
    for (let i = 0; i < 200; i++) {
      const data = utf8Encode(`message ${i}`);
      const sig = await signer.sign(data);
      assert.equal(sig.length, 64);
      assert.ok(toBig(sig.subarray(32)) <= HALF_N);
      if (i < 20) assert.equal(await webCryptoVerifier.verify(signer.publicJwk, data, sig), true);
    }
  });

  test('keeps its own copy of the key', async () => {
    const key = generateSecretKey(countingRandom());
    const signer = createNobleSigner(key);
    const before = await signer.sign(DATA);
    key.fill(0);
    assert.deepEqual(await signer.sign(DATA), before);
  });

  test('rejects invalid secret keys', () => {
    for (const bad of [new Uint8Array(32), toBytes32(N), toBytes32(N + 1n), new Uint8Array(31).fill(1), new Uint8Array(33).fill(1)]) {
      assert.throws(() => createNobleSigner(bad), TypeError);
    }
  });
});

describe('generateSecretKey', () => {
  test('one call to the injected RandomSource, 48 bytes, valid scalar', () => {
    const random = countingRandom();
    const key = generateSecretKey(random);
    assert.deepEqual(random.calls, [48]);
    assert.equal(key.length, 32);
    assert.ok(P256.utils.isValidSecretKey(key));
  });

  test('all-zero and all-0xFF sources neither hang nor yield an invalid scalar', () => {
    for (const value of [0x00, 0xff]) {
      const key = generateSecretKey(constantRandom(value));
      assert.ok(P256.utils.isValidSecretKey(key), `fill ${value}`);
      assert.ok(toBig(key) >= 1n && toBig(key) < N);
    }
    // Mapping is (seed mod (n - 1)) + 1, so an all-zero seed gives the scalar 1.
    assert.equal(toBig(generateSecretKey(constantRandom(0))), 1n);
  });

  test('a RandomSource returning the wrong length is refused', () => {
    assert.throws(() => generateSecretKey({ bytes: () => new Uint8Array(32) }), TypeError);
    assert.throws(() => generateSecretKey({ bytes: () => [] as unknown as Uint8Array }), TypeError);
  });

  test('nothing in the adapters calls globalThis.crypto.getRandomValues', async (t) => {
    const spy = t.mock.method(globalThis.crypto, 'getRandomValues');
    const signer = createNobleSigner(generateSecretKey(seededRandom(1)));
    const sig = await signer.sign(DATA);
    assert.equal(await nobleVerifier.verify(signer.publicJwk, DATA, sig), true);
    const der = createDerSigningAdapter({ publicJwk: signer.publicJwk, signDer: async () => rawSignatureToDer(sig) });
    assert.deepEqual(await der.sign(DATA), sig);
    assert.equal(spy.mock.callCount(), 0);
  });
});

describe('nobleHasher', () => {
  test('SHA-256 of "abc" (FIPS 180-2)', async () => {
    assert.deepEqual(await nobleHasher.sha256(utf8Encode('abc')), hexDecode('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
  });
});

describe('createDerSigningAdapter', () => {
  // OpenSSL via node:crypto plays the hardware keystore: it returns DER and does not normalise S.
  function opensslKey() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const { x, y } = publicKey.export({ format: 'jwk' });
    const publicJwk: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: x!, y: y! };
    return { publicJwk, signDer: async (data: Uint8Array) => new Uint8Array(nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'der' })) };
  }

  test('OpenSSL DER (high-S, leading-zero and short integers) becomes r||s that verifies', async () => {
    const key = opensslKey();
    const signer = createDerSigningAdapter(key);
    assert.deepEqual(signer.publicJwk, key.publicJwk);
    assert.equal('x5c' in signer, false);
    const seen = { highS: false, leadingZero: false, short: false };
    for (let i = 0; i < 3000 && !(seen.highS && seen.leadingZero && seen.short); i++) {
      const data = utf8Encode(`m${i}`);
      const der = await key.signDer(data);
      const raw = await createDerSigningAdapter({ publicJwk: key.publicJwk, signDer: async () => der }).sign(data);
      assert.equal(raw.length, 64);
      assert.deepEqual(raw, derSignatureToRaw(der));
      const rLen = der[3]!;
      const sLen = der[5 + rLen]!;
      const highS = toBig(raw.subarray(32)) > HALF_N;
      const leadingZero = rLen === 33 || sLen === 33;
      const short = rLen < 32 || sLen < 32;
      if ((highS && !seen.highS) || (leadingZero && !seen.leadingZero) || (short && !seen.short) || i < 5) {
        assert.equal(await nobleVerifier.verify(key.publicJwk, data, raw), true);
        assert.equal(await webCryptoVerifier.verify(key.publicJwk, data, raw), true);
      }
      seen.highS ||= highS;
      seen.leadingZero ||= leadingZero;
      seen.short ||= short;
    }
    assert.deepEqual(seen, { highS: true, leadingZero: true, short: true });
    // The adapter itself, end to end.
    assert.equal(await nobleVerifier.verify(key.publicJwk, DATA, await signer.sign(DATA)), true);
  });

  test('malformed DER from the keystore is refused', async () => {
    const key = opensslKey();
    const der = await key.signDer(DATA);
    const cases = [
      new Uint8Array([...der, 0]), // trailing byte
      der.subarray(0, der.length - 1), // truncated
      new Uint8Array([0x30, 0x81, der[1]!, ...der.subarray(2)]), // non-minimal length
      rawSignatureToDer(rs(1n, 1n)).map((b, i) => (i === 0 ? 0x31 : b)), // not a SEQUENCE
      await createNobleSigner(generateSecretKey(countingRandom())).sign(DATA), // raw instead of DER
      new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]), // r = 0
    ];
    for (const bad of cases) {
      await assert.rejects(createDerSigningAdapter({ publicJwk: key.publicJwk, signDer: async () => bad }).sign(DATA), TypeError);
    }
  });

  test('refuses an invalid public JWK', () => {
    const key = opensslKey();
    const y = base64UrlDecode(key.publicJwk.y);
    y[0]! ^= 1;
    assert.throws(() => createDerSigningAdapter({ ...key, publicJwk: { ...key.publicJwk, y: base64UrlEncode(y) } }), TypeError);
  });
});
