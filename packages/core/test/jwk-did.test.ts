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
