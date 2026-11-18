// The worked examples of RFC 9901 (SD-JWT), extracted by script into fixtures/rfc9901.ts:
// our digest and sd_hash functions and our JWS verification reproduce them.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeJws, normalizeEcPublicJwk, utf8Decode, verifyJws } from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { disclosureDigest, sdHashOf } from '../dist/sd-jwt/holder-binding.js';
import { RFC9901_DISCLOSURES, RFC9901_ISSUER_JWK, RFC9901_KB_PAYLOAD, RFC9901_PRESENTATION } from './fixtures/rfc9901.js';

test('section 5.1: every disclosure hashes to the digest printed in the RFC', async () => {
  assert.equal(RFC9901_DISCLOSURES.length, 10);
  for (const { digest, disclosure } of RFC9901_DISCLOSURES) assert.equal(await disclosureDigest(disclosure, webCryptoHasher), digest, disclosure);
});

test('section 5.2: the SD-JWT+KB verifies (issuer and holder signatures, digests, sd_hash)', async () => {
  const parts = RFC9901_PRESENTATION.split('~');
  assert.equal(parts.length, 6);
  const issuer = decodeJws(parts[0], 16_384);
  const kb = decodeJws(parts[5], 4_096);
  assert.ok(issuer.ok && kb.ok);
  // The example uses typ example+sd-jwt and nested/array disclosures, so verifyPresentation (which
  // requires dc+sd-jwt, x5c and top-level disclosures) does not apply; its building blocks do.
  assert.equal(await verifyJws(issuer.jws, normalizeEcPublicJwk(RFC9901_ISSUER_JWK)!, webCryptoVerifier), null);
  const payload = JSON.parse(utf8Decode(issuer.jws.payload)) as { _sd: string[]; nationalities: { '...': string }[]; cnf: { jwk: unknown }; _sd_alg: string };
  assert.equal(payload._sd_alg, 'sha-256');
  const holderKey = normalizeEcPublicJwk(payload.cnf.jwk);
  assert.ok(holderKey, 'the cnf key is a valid P-256 key');
  assert.equal(await verifyJws(kb.jws, holderKey, webCryptoVerifier), null);
  const kbPayload = JSON.parse(utf8Decode(kb.jws.payload));
  assert.deepEqual(kbPayload, RFC9901_KB_PAYLOAD);
  assert.equal(await sdHashOf(RFC9901_PRESENTATION.slice(0, RFC9901_PRESENTATION.lastIndexOf('~') + 1), webCryptoHasher), RFC9901_KB_PAYLOAD.sd_hash);
  // Three object-property disclosures referenced by the top-level _sd, one array element by "...".
  const referenced = [...payload._sd, ...payload.nationalities.map((n) => n['...'])];
  for (const d of parts.slice(1, 5)) assert.ok(referenced.includes(await disclosureDigest(d, webCryptoHasher)), d);
  // A one-byte change of the presentation breaks sd_hash.
  assert.notEqual(await sdHashOf(RFC9901_PRESENTATION.slice(0, RFC9901_PRESENTATION.lastIndexOf('~')), webCryptoHasher), RFC9901_KB_PAYLOAD.sd_hash);
});
