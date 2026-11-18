// JWS and the ES256 crypto adapters (ADR-0006 section 6, docs/architecture.md section 6).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  base64UrlDecode,
  base64UrlEncode,
  checkJwsAlgorithm,
  decodeJws,
  ErrorCodes,
  signJws,
  utf8Encode,
  verifyJwsSignature,
  type DecodedJws,
  type EcPublicJwk,
  type Signer,
  type Verifier,
} from '@identra/sdk-core';
import { p256 } from '@noble/curves/nist.js';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleSigner, nobleVerifier, P256_N } from './helpers/noble.js';

// RFC 7515 Appendix A.3, extracted from https://www.rfc-editor.org/rfc/rfc7515.txt.
const RFC_A3_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
} as const;
const RFC_A3_JWS =
  'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
// RFC 7515 Appendix A.1 (HS256), same source.
const RFC_A1_JWS =
  'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

const RFC_PUBLIC: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: RFC_A3_JWK.x, y: RFC_A3_JWK.y };
const VERIFIERS: [string, Verifier][] = [
  ['webcrypto', webCryptoVerifier],
  ['noble', nobleVerifier],
];

function decoded(compact: string): DecodedJws {
  const r = decodeJws(compact);
  assert.ok(r.ok, `decodeJws failed: ${r.ok ? '' : r.detail}`);
  return r.jws;
}
const flip = (b: Uint8Array, i: number) => {
  const c = b.slice();
  c[i]! ^= 0x01;
  return c;
};

async function signers(): Promise<[string, Signer][]> {
  const rfcKey = await crypto.subtle.importKey('jwk', { ...RFC_A3_JWK }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const fresh = await generateWebCryptoKeyPair();
  return [
    ['webcrypto (RFC A.3 key)', await createWebCryptoSigner({ privateKey: rfcKey })],
    ['webcrypto (fresh key)', await createWebCryptoSigner({ privateKey: fresh.privateKey })],
    ['noble (RFC A.3 key)', nobleSigner(base64UrlDecode(RFC_A3_JWK.d))],
  ];
}

describe('RFC 7515 Appendix A.3 (ES256)', () => {
  for (const [name, verifier] of VERIFIERS) {
    test(`verifies with the ${name} verifier, and fails after a one-byte change`, async () => {
      const jws = decoded(RFC_A3_JWS);
      assert.deepEqual(jws.header, { alg: 'ES256' });
      assert.equal(checkJwsAlgorithm(jws.header), null);
      assert.equal(await verifyJwsSignature(jws, RFC_PUBLIC, verifier), true);
      assert.equal(await verifyJwsSignature({ ...jws, signingInput: flip(jws.signingInput, 30) }, RFC_PUBLIC, verifier), false);
      assert.equal(await verifyJwsSignature({ ...jws, signature: flip(jws.signature, 10) }, RFC_PUBLIC, verifier), false);
    });
  }
});

describe('sign -> verify -> tamper, across backends', () => {
  test('every signer verifies on every verifier; a one-byte change of payload or signature fails', async () => {
    for (const [sName, signer] of await signers()) {
      const compact = await signJws({ typ: 'JWT' }, utf8Encode('{"iss":"https://example.test"}'), signer);
      const [h, p, s] = compact.split('.') as [string, string, string];
      const tamperedPayload = `${h}.${base64UrlEncode(flip(base64UrlDecode(p), 3))}.${s}`;
      const tamperedSignature = `${h}.${p}.${base64UrlEncode(flip(base64UrlDecode(s), 40))}`;
      for (const [vName, verifier] of VERIFIERS) {
        const label = `${sName} -> ${vName}`;
        assert.equal(await verifyJwsSignature(decoded(compact), signer.publicJwk, verifier), true, label);
        assert.equal(await verifyJwsSignature(decoded(tamperedPayload), signer.publicJwk, verifier), false, label);
        assert.equal(await verifyJwsSignature(decoded(tamperedSignature), signer.publicJwk, verifier), false, label);
      }
    }
  });

  test('a high-S signature still verifies on both backends', async () => {
    const [, signer] = (await signers())[0]!;
    const data = utf8Encode('high-S');
    const sig = await signer.sign(data);
    const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
    const high = s > P256_N / 2n ? s : P256_N - s;
    const highSig = new Uint8Array(64);
    highSig.set(sig.subarray(0, 32));
    highSig.set(Buffer.from(high.toString(16).padStart(64, '0'), 'hex'), 32);
    const pub = Buffer.concat([Buffer.from([4]), base64UrlDecode(signer.publicJwk.x), base64UrlDecode(signer.publicJwk.y)]);
    assert.equal(p256.verify(highSig, data, pub), false, 'noble defaults reject it, so it really is high-S');
    for (const [name, verifier] of VERIFIERS) assert.equal(await verifier.verify(signer.publicJwk, data, highSig), true, name);
  });
});

describe('algorithm allow-list', () => {
  test('alg none and HS256 (RFC 7515 A.1) are ALG_NOT_ALLOWED', () => {
    const none = `${base64UrlEncode(utf8Encode('{"alg":"none"}'))}.${base64UrlEncode(utf8Encode('{}'))}.${base64UrlEncode(new Uint8Array(64))}`;
    assert.equal(checkJwsAlgorithm(decoded(none).header), ErrorCodes.ALG_NOT_ALLOWED);
    assert.equal(checkJwsAlgorithm(decoded(RFC_A1_JWS).header), ErrorCodes.ALG_NOT_ALLOWED);
  });
  test('every other value is ALG_NOT_ALLOWED', () => {
    for (const alg of ['EdDSA', 'Ed25519', 'ES384', 'ES512', 'RS256', 'PS256', 'HS512', 'es256', 'ES256 ', '', null, ['ES256'], undefined]) {
      assert.equal(checkJwsAlgorithm(alg === undefined ? {} : { alg }), ErrorCodes.ALG_NOT_ALLOWED, String(alg));
    }
  });
  test('an unsigned JWS (empty signature part) is MALFORMED', () => {
    const r = decodeJws(`${base64UrlEncode(utf8Encode('{"alg":"none"}'))}.${base64UrlEncode(utf8Encode('{}'))}.`);
    assert.equal(r.ok ? null : r.code, ErrorCodes.MALFORMED);
  });
});

describe('decodeJws is strict', () => {
  const h = base64UrlEncode(utf8Encode('{"alg":"ES256"}'));
  const p = base64UrlEncode(utf8Encode('{}'));
  const s = base64UrlEncode(new Uint8Array(64));
  const enc = (json: string) => base64UrlEncode(utf8Encode(json));
  const bad: [string, unknown][] = [
    ['two parts', `${h}.${p}`],
    ['four parts', `${h}.${p}.${s}.${s}`],
    ['empty header', `.${p}.${s}`],
    ['empty payload', `${h}..${s}`],
    ['padding', `${h}=.${p}.${s}`],
    ['standard base64 alphabet', `${h}.${p}.${s.slice(0, -1)}+`],
    ['whitespace', `${h} .${p}.${s}`],
    ['header not JSON', `${enc('{alg:ES256}')}.${p}.${s}`],
    ['header is an array', `${enc('["ES256"]')}.${p}.${s}`],
    ['header is null', `${enc('null')}.${p}.${s}`],
    ['header is a string', `${enc('"ES256"')}.${p}.${s}`],
    ['header has crit', `${enc('{"alg":"ES256","crit":["b64"],"b64":false}')}.${p}.${s}`],
    ['header is not UTF-8', `${base64UrlEncode(Uint8Array.from([0x7b, 0xff, 0x7d]))}.${p}.${s}`],
    ['not a string', 42],
  ];
  for (const [name, input] of bad) {
    test(name, () => {
      const r = decodeJws(input);
      assert.equal(r.ok ? null : r.code, ErrorCodes.MALFORMED);
    });
  }
});

describe('signJws', () => {
  test('sets alg from the signer and adds the signer x5c', async () => {
    const signer = { ...nobleSigner(base64UrlDecode(RFC_A3_JWK.d)), x5c: ['MIIB', 'MIIC'] };
    const jws = decoded(await signJws({ typ: 'dc+sd-jwt' }, utf8Encode('{}'), signer));
    assert.deepEqual(jws.header, { alg: 'ES256', typ: 'dc+sd-jwt', x5c: ['MIIB', 'MIIC'] });
  });
  test('refuses alg or x5c from the caller, a non-ES256 signer and a non-r||s signature', async () => {
    const signer = nobleSigner(base64UrlDecode(RFC_A3_JWK.d));
    await assert.rejects(signJws({ alg: 'none' }, utf8Encode('{}'), signer), TypeError);
    await assert.rejects(signJws({ x5c: [] }, utf8Encode('{}'), signer), TypeError);
    await assert.rejects(signJws({}, utf8Encode('{}'), { ...signer, alg: 'ES384' as 'ES256' }), TypeError);
    await assert.rejects(signJws({}, utf8Encode('{}'), { ...signer, sign: async () => new Uint8Array(70) }), TypeError);
  });
  test('verifyJwsSignature returns false for a signature that is not 64 bytes', async () => {
    const jws = decoded(RFC_A3_JWS);
    assert.equal(await verifyJwsSignature({ ...jws, signature: jws.signature.subarray(0, 63) }, RFC_PUBLIC, webCryptoVerifier), false);
  });
});
