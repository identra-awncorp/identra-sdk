// JWK helpers, did:jwk and resolveDidVerificationKey.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  base64UrlEncode,
  didJwkResolver,
  ErrorCodes,
  jwkThumbprint,
  normalizeEcPublicJwk,
  resolveDidVerificationKey,
  utf8Encode,
  type DidResolver,
  type EcPublicJwk,
} from '@identra/sdk-core';
import { webCryptoHasher } from '@identra/sdk-core/webcrypto';

// RFC 7515 Appendix A.3 public key.
const JWK: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
const didOf = (jwk: unknown) => `did:jwk:${base64UrlEncode(utf8Encode(JSON.stringify(jwk)))}`;

test('normalizeEcPublicJwk keeps only kty, crv, x, y of a P-256 public key', () => {
  assert.deepEqual(normalizeEcPublicJwk({ ...JWK, kid: 'k', alg: 'ES256', use: 'sig' }), JWK);
  const rejected: unknown[] = [
    null,
    'jwk',
    [JWK],
    { ...JWK, d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI' },
    { ...JWK, crv: 'P-384' },
    { ...JWK, crv: 'secp256k1' },
    { ...JWK, kty: 'OKP' },
    { kty: 'oct', k: 'AAAA' },
    { ...JWK, x: JWK.x.slice(1) },
    { ...JWK, x: `${JWK.x}=` },
    { ...JWK, y: 42 },
    { kty: 'EC', crv: 'P-256', x: JWK.x },
  ];
  for (const r of rejected) assert.equal(normalizeEcPublicJwk(r), null, JSON.stringify(r));
});

test('jwkThumbprint hashes the RFC 7638 canonical form', async () => {
  const canonical = `{"crv":"P-256","kty":"EC","x":"${JWK.x}","y":"${JWK.y}"}`;
  const expected = createHash('sha256').update(canonical).digest('base64url');
  assert.equal(await jwkThumbprint({ y: JWK.y, x: JWK.x, crv: 'P-256', kty: 'EC' }, webCryptoHasher), expected);
  await assert.rejects(jwkThumbprint({ ...JWK, crv: 'P-384' as 'P-256' }, webCryptoHasher), TypeError);
});

test('did:jwk resolves to a document whose assertionMethod key is the JWK', async () => {
  const did = didOf(JWK);
  const r = await didJwkResolver.resolve(did);
  assert.equal(r.didDocument?.id, did);
  assert.deepEqual(r.didDocument?.assertionMethod, [`${did}#0`]);
  const key = await resolveDidVerificationKey(`${did}#0`, didJwkResolver);
  assert.deepEqual(key, { ok: true, publicJwk: JWK });
});

test('did:jwk errors', async () => {
  for (const did of ['did:web:example.com', didOf({ ...JWK, crv: 'P-384' }), didOf({ ...JWK, d: 'x' }), 'did:jwk:!!', 'did:jwk:']) {
    const r = await didJwkResolver.resolve(did);
    assert.equal(r.didDocument, null, did);
    assert.ok(r.didResolutionMetadata.error, did);
  }
});

test('resolveDidVerificationKey: DID_RESOLUTION_FAILED', async () => {
  const fail = async (kid: string, resolver: DidResolver = didJwkResolver) => {
    const r = await resolveDidVerificationKey(kid, resolver);
    return r.ok ? null : r.code;
  };
  assert.equal(await fail('did:web:example.com#key-1'), ErrorCodes.DID_RESOLUTION_FAILED);
  assert.equal(await fail(`${didOf({ ...JWK, kty: 'RSA' })}#0`), ErrorCodes.DID_RESOLUTION_FAILED);
  const throwing: DidResolver = { resolve: async () => Promise.reject(new Error('network down')) };
  assert.equal(await fail(`${didOf(JWK)}#0`, throwing), ErrorCodes.DID_RESOLUTION_FAILED);
  const otherDocument: DidResolver = { resolve: async (d) => didJwkResolver.resolve(d === didOf(JWK) ? didOf({ ...JWK, x: JWK.y }) : d) };
  assert.equal(await fail(`${didOf(JWK)}#0`, otherDocument), ErrorCodes.DID_RESOLUTION_FAILED);
});

test('resolveDidVerificationKey: KEY_NOT_FOUND', async () => {
  const did = didOf(JWK);
  const code = async (kid: unknown, resolver: DidResolver = didJwkResolver) => {
    const r = await resolveDidVerificationKey(kid, resolver);
    return r.ok ? null : r.code;
  };
  assert.equal(await code(did), ErrorCodes.KEY_NOT_FOUND, 'no fragment');
  assert.equal(await code(`${did}#1`), ErrorCodes.KEY_NOT_FOUND, 'unknown fragment');
  assert.equal(await code(undefined), ErrorCodes.KEY_NOT_FOUND, 'not a string');
  const notAsserted: DidResolver = {
    async resolve(d) {
      const r = await didJwkResolver.resolve(d);
      return { ...r, didDocument: { ...r.didDocument!, assertionMethod: [] } };
    },
  };
  assert.equal(await code(`${did}#0`, notAsserted), ErrorCodes.KEY_NOT_FOUND, 'not in assertionMethod');
});

// RFC 9449 (DPoP) Figures 4 and 9: an EC P-256 key and its RFC 7638 thumbprint ("jkt"), taken from
// https://www.rfc-editor.org/rfc/rfc9449.txt. (RFC 7638's own example is an RSA key, which is not supported.)
const RFC9449_JWK: EcPublicJwk = { kty: 'EC', crv: 'P-256', x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs', y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA' };
const RFC9449_JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

test('jwkThumbprint reproduces the RFC 9449 vector', async () => {
  assert.equal(await jwkThumbprint(RFC9449_JWK, webCryptoHasher), RFC9449_JKT);
});

test('normalizeEcPublicJwk refuses points off the curve and never throws', async () => {
  const { p256 } = await import('@noble/curves/nist.js');
  for (let i = 0; i < 20; i++) {
    const point = p256.getPublicKey(p256.utils.randomSecretKey(), false);
    const jwk = { kty: 'EC', crv: 'P-256', x: base64UrlEncode(point.subarray(1, 33)), y: base64UrlEncode(point.subarray(33)) };
    assert.ok(normalizeEcPublicJwk(jwk), 'a random noble point is on the curve');
    const y = point.slice(33);
    y[31] = y[31]! ^ 1;
    assert.equal(normalizeEcPublicJwk({ ...jwk, y: base64UrlEncode(y) }), null, 'y changed');
  }
  const zero = base64UrlEncode(new Uint8Array(32));
  const p = base64UrlEncode(Uint8Array.from(Buffer.from('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 'hex')));
  for (const bad of [{ ...JWK, x: zero, y: zero }, { ...JWK, x: p }, { ...JWK, y: p }]) assert.equal(normalizeEcPublicJwk(bad), null);
  const throwing = Object.defineProperty({}, 'kty', { get: () => { throw new Error('getter'); } });
  assert.equal(normalizeEcPublicJwk(throwing), null);
});

test('did:jwk honours "use": enc keys only for keyAgreement, sig keys never for it', async () => {
  const enc = (await didJwkResolver.resolve(didOf({ ...JWK, use: 'enc' }))).didDocument!;
  assert.equal(enc.assertionMethod, undefined);
  assert.deepEqual(enc.keyAgreement, [`${didOf({ ...JWK, use: 'enc' })}#0`]);
  assert.equal((await resolveDidVerificationKey(`${didOf({ ...JWK, use: 'enc' })}#0`, didJwkResolver)).ok, false);
  const sig = (await didJwkResolver.resolve(didOf({ ...JWK, use: 'sig' }))).didDocument!;
  assert.equal(sig.keyAgreement, undefined);
  assert.ok((await resolveDidVerificationKey(`${didOf({ ...JWK, use: 'sig' })}#0`, didJwkResolver)).ok);
  assert.equal((await didJwkResolver.resolve(didOf({ ...JWK, use: 'other' }))).didDocument, null);
});

test('resolveDidVerificationKey: odd resolver output never throws, a controller mismatch is KEY_NOT_FOUND', async () => {
  const did = didOf(JWK);
  const kid = `${did}#0`;
  const base = (await didJwkResolver.resolve(did)).didDocument!;
  const answering = (didDocument: unknown, meta: unknown = {}): DidResolver => ({ resolve: async () => ({ didDocument, didDocumentMetadata: {}, didResolutionMetadata: meta }) as never });
  const code = async (resolver: DidResolver) => {
    const r = await resolveDidVerificationKey(kid, resolver);
    return r.ok ? null : r.code;
  };
  assert.equal(await code({ resolve: async () => null as never }), ErrorCodes.DID_RESOLUTION_FAILED);
  assert.equal(await code({ resolve: async () => 'nonsense' as never }), ErrorCodes.DID_RESOLUTION_FAILED);
  assert.equal(await code(answering(base, null)), ErrorCodes.DID_RESOLUTION_FAILED);
  assert.equal(await code(answering(base, { error: 'notFound' })), ErrorCodes.DID_RESOLUTION_FAILED);
  assert.equal(await code(answering({ ...base, assertionMethod: `xx${kid}xx` })), ErrorCodes.KEY_NOT_FOUND, 'a string assertionMethod is not a list');
  assert.equal(await code(answering({ ...base, verificationMethod: { 0: base.verificationMethod![0] } })), ErrorCodes.KEY_NOT_FOUND);
  assert.equal(await code(answering({ ...base, verificationMethod: [{ ...base.verificationMethod![0]!, controller: 'did:jwk:other' }] })), ErrorCodes.KEY_NOT_FOUND);
  assert.equal(await code(answering({ ...base, verificationMethod: [null] })), ErrorCodes.KEY_NOT_FOUND);
  const { p256 } = await import('@noble/curves/nist.js');
  const point = p256.getPublicKey(p256.utils.randomSecretKey(), false);
  const otherDid = didOf({ kty: 'EC', crv: 'P-256', x: base64UrlEncode(point.subarray(1, 33)), y: base64UrlEncode(point.subarray(33)) });
  const otherDoc = (await didJwkResolver.resolve(otherDid)).didDocument!;
  assert.ok(otherDoc, 'a valid document, but for another DID');
  assert.equal(await code(answering({ ...otherDoc, assertionMethod: [kid], verificationMethod: [{ ...otherDoc.verificationMethod![0]!, id: kid, controller: did }] })), ErrorCodes.DID_RESOLUTION_FAILED, 'document id differs from the DID');
  assert.equal(await code(answering(base)), null);
});
