// createStatusListService: random allocation without repeats, revoked is final, re-signing rules,
// and tokens that verify with the core verifier against a trust list made by the trust-list service.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSignedTrustListRegistry, verifyStatusListToken, type HttpFetch, type RandomSource } from '@identra/sdk-core';
import { webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createFileKeyStore, createMemoryStatusListStorage, createStatusListService, createTrustListService, StatusListFullError, StatusRevokedError } from '@identra/sdk-server';
import { fakeClock, freshDemoPki, issuerUri, trustListSource, validatorFor } from './helpers.js';

const DEMO = freshDemoPki();
const keyStore = createFileKeyStore(DEMO);
const URI = `${issuerUri('truong-mau')}/status/1`;
// Made before any clock below starts: validFrom is the moment the script runs.
const TRUST_CONTENT = trustListSource(DEMO);
const setup = (random: RandomSource = webCryptoRandom) => {
  const clock = fakeClock();
  const storage = createMemoryStatusListStorage();
  return { clock, storage, service: createStatusListService({ issuerUri, keyStore, storage, random, clock }) };
};

test('1000 concurrent allocations: random, in range, never the same index twice', async () => {
  const { service, storage } = setup();
  const got = await Promise.all(Array.from({ length: 1000 }, () => service.allocate('truong-mau')));
  assert.ok(got.every((g) => g.uri === URI && Number.isSafeInteger(g.idx) && g.idx >= 0 && g.idx < 131_072));
  assert.equal(new Set(got.map((g) => g.idx)).size, 1000);
  assert.equal(storage.reservedCount('truong-mau', 1), 1000);
  assert.ok(got.some((g) => g.idx > 65_536) && got.some((g) => g.idx < 65_536), 'spread over the list');
  const sorted = got.map((g) => g.idx);
  assert.notDeepEqual(sorted, [...sorted].sort((a, b) => a - b), 'not in issuance order');
});

test('collisions are retried through storage.reserve; a list with no free index found is an error', async () => {
  // Only three distinct indexes can ever come out of this source.
  let i = 0;
  const three: RandomSource = { bytes: (n) => new Uint8Array(n).fill(i++ % 3) };
  const { service } = setup(three);
  const got = await Promise.all([1, 2, 3].map(() => service.allocate('truong-mau')));
  assert.equal(new Set(got.map((g) => g.idx)).size, 3);
  await assert.rejects(service.allocate('truong-mau'), StatusListFullError);
});

test('status changes; revoked is final', async () => {
  const { service, storage } = setup();
  await service.setStatus('truong-mau', 1, 5, 'suspended');
  await service.setStatus('truong-mau', 1, 5, 'valid');
  await service.setStatus('truong-mau', 1, 5, 'revoked');
  await service.setStatus('truong-mau', 1, 5, 'revoked');
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'valid'), StatusRevokedError);
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'suspended'), StatusRevokedError);
  assert.equal((await storage.load('truong-mau', 1))?.version, 3, 'no-op changes are not written');
  await assert.rejects(service.setStatus('truong-mau', 1, 131_072, 'revoked'), RangeError);
  await assert.rejects(service.setStatus('truong-mau', 1, 6, 'gone' as 'valid'), TypeError);
  await assert.rejects(service.setStatus('../x', 1, 6, 'revoked'), TypeError);
  assert.throws(() => service.uri('truong-mau', 0), TypeError);
});

test('concurrent changes of one list are all kept (optimistic concurrency)', async () => {
  const { service, storage } = setup();
  await Promise.all([1, 2, 3, 4].map((idx) => service.setStatus('truong-mau', 1, idx, 'revoked')));
  assert.equal((await storage.load('truong-mau', 1))?.version, 4);
  for (const idx of [1, 2, 3, 4]) await assert.rejects(service.setStatus('truong-mau', 1, idx, 'valid'), StatusRevokedError);
});

test('the token verifies with the core verifier; re-signed on change and after one hour', async () => {
  const { service, clock } = setup();
  const trust = createTrustListService({ source: () => TRUST_CONTENT, keyStore, clock });
  const fetch: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: () => trust.token() });
  const chainValidator = validatorFor(DEMO);
  const trustRegistry = createSignedTrustListRegistry({ url: 'https://api-identra.awncorp.vn/trust-list', fetch, verifier: webCryptoVerifier, chainValidator, clock, maxAgeSeconds: 0 });
  const read = async (token: string, issuer = 'VATVN-0100000001') => {
    const r = await verifyStatusListToken(token, { uri: URI, issuer: { maToChuc: issuer }, chainValidator, trustRegistry, verifier: webCryptoVerifier, now: clock.now() });
    assert.ok(r.ok, r.ok ? '' : `${r.reason}: ${r.detail}`);
    return r;
  };

  const t1 = await service.token('truong-mau', 1);
  assert.equal((await read(t1)).list.getStatus(42), 0);
  assert.equal(await service.token('truong-mau', 1), t1, 'unchanged: the cached token');
  await service.setStatus('truong-mau', 1, 42, 'revoked');
  const t2 = await service.token('truong-mau', 1);
  assert.notEqual(t2, t1);
  assert.equal((await read(t2)).list.getStatus(42), 1);
  clock.advance(3599);
  assert.equal(await service.token('truong-mau', 1), t2);
  clock.advance(1);
  const t3 = await service.token('truong-mau', 1);
  assert.notEqual(t3, t2);
  assert.equal((await read(t3)).iat, Math.floor(clock.now().getTime() / 1000));
  // Signed with the status certificate of Truong Mau: not valid for another organisation's credentials.
  const other = await verifyStatusListToken(t3, { uri: URI, issuer: { maToChuc: 'VATVN-0100000002' }, chainValidator, trustRegistry, verifier: webCryptoVerifier, now: clock.now() });
  assert.equal(other.ok, false);
});
