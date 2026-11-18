// createStatusListService: random allocation without repeats and with rollover, status changes of
// allocated indexes only (revoked final), tokens only for existing lists with strictly increasing
// iat, re-signing rules, and verification with the core verifier against the trust-list service.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createSignedTrustListRegistry, STATUS_LIST_BYTES, verifyStatusListToken, type HttpFetch, type RandomSource,
} from '@identra/sdk-core';
import { webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  createFileKeyStore, createMemoryStatusListStorage, createStatusListService, createTrustListService, StatusIndexNotAllocatedError,
  StatusListFullError, StatusRevokedError, type StatusListStorage,
} from '@identra/sdk-server';
import { fakeClock, freshDemoPki, issuerUri, trustListSource, validatorFor } from './helpers.js';

const DEMO = freshDemoPki();
const keyStore = createFileKeyStore(DEMO);
const URI = (n = 1) => `${issuerUri('truong-mau')}/status/${n}`;
const TRUST_CONTENT = trustListSource(DEMO);
const setup = (random: RandomSource = webCryptoRandom, storage = createMemoryStatusListStorage()) => {
  const clock = fakeClock();
  return { clock, storage, service: createStatusListService({ issuerUri, keyStore, storage, random, clock }) };
};
/** Bytes 0-2 of the source give the index (low 17 bits): a scripted sequence of indexes. */
const indexes = (...list: number[]): RandomSource => {
  let i = 0;
  return { bytes: () => { const v = list[i++ % list.length]!; return new Uint8Array([v >> 16, (v >> 8) & 255, v & 255]); } };
};
const iatOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()).iat as number;

test('1000 concurrent allocations: random, in range, never the same index twice', async () => {
  const { service, storage } = setup();
  const got = await Promise.all(Array.from({ length: 1000 }, () => service.allocate('truong-mau')));
  assert.ok(got.every((g) => g.uri === URI() && Number.isSafeInteger(g.idx) && g.idx >= 0 && g.idx < 131_072));
  assert.equal(new Set(got.map((g) => g.idx)).size, 1000);
  assert.equal(storage.reservedCount('truong-mau', 1), 1000);
  assert.ok(got.some((g) => g.idx > 65_536) && got.some((g) => g.idx < 65_536), 'spread over the list');
  const order = got.map((g) => g.idx);
  assert.notDeepEqual(order, [...order].sort((a, b) => a - b), 'not in issuance order');
});

test('collisions are retried; when the draws fail, allocation rolls over to the next list', async () => {
  const { service } = setup(indexes(7, 8, 9));
  const got = await Promise.all([1, 2, 3].map(() => service.allocate('truong-mau')));
  assert.deepEqual(got.map((g) => g.idx).sort(), [7, 8, 9]);
  const next = await service.allocate('truong-mau');
  assert.equal(next.uri, URI(2));
  assert.equal(next.n, 2);
  assert.ok([7, 8, 9].includes(next.idx));
});

test('at 99 % fill every allocation succeeds (in list 1 or by rolling over to list 2)', async () => {
  const storage = createMemoryStatusListStorage();
  for (let idx = 0; idx < 129_761; idx++) await storage.reserve('truong-mau', 1, idx);
  const { service } = setup(webCryptoRandom, storage);
  const got = [];
  for (let i = 0; i < 200; i++) got.push(await service.allocate('truong-mau'));
  assert.ok(got.every((g) => (g.uri === URI(1) && g.idx >= 129_761) || g.uri === URI(2)));
  assert.ok(got.some((g) => g.uri === URI(2)), 'rolled over');
  assert.equal(new Set(got.map((g) => `${g.uri} ${g.idx}`)).size, 200);
});

test('StatusListFullError only when the next list fails too', async () => {
  const never: StatusListStorage = { ...createMemoryStatusListStorage(), reserve: async () => false };
  const { service } = setup(webCryptoRandom, never as ReturnType<typeof createMemoryStatusListStorage>);
  await assert.rejects(service.allocate('truong-mau'), StatusListFullError);
});

test('an index that is not 0 is never handed out, so no credential is born revoked', async () => {
  const { service, storage } = setup(indexes(5, 6));
  const bytes = new Uint8Array(STATUS_LIST_BYTES);
  bytes[1] = 0b01 << 2; // entry 5 (bits 2-3 of byte 1) revoked without an allocation, as old data might be
  assert.equal(await storage.save('truong-mau', 1, bytes, null), true);
  assert.deepEqual(await service.allocate('truong-mau'), { uri: URI(1), n: 1, idx: 6 });
});

test('status changes only for allocated indexes; revoked is final', async () => {
  const { service, storage } = setup(indexes(5));
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'revoked'), StatusIndexNotAllocatedError);
  assert.deepEqual(await service.allocate('truong-mau'), { uri: URI(1), n: 1, idx: 5 });
  const v0 = (await storage.load('truong-mau', 1))!.version;
  await service.setStatus('truong-mau', 1, 5, 'suspended');
  await service.setStatus('truong-mau', 1, 5, 'valid');
  await service.setStatus('truong-mau', 1, 5, 'revoked');
  await service.setStatus('truong-mau', 1, 5, 'revoked');
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'valid'), StatusRevokedError);
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'suspended'), StatusRevokedError);
  assert.equal((await storage.load('truong-mau', 1))?.version, v0 + 3, 'no-op changes are not written');
  await assert.rejects(service.setStatus('truong-mau', 1, 131_072, 'revoked'), RangeError);
  await assert.rejects(service.setStatus('truong-mau', 1, 5, 'gone' as 'valid'), TypeError);
  await assert.rejects(service.setStatus('../x', 1, 5, 'revoked'), TypeError);
  for (const n of [0, 1_000_000_000, 1.5]) assert.throws(() => service.uri('truong-mau', n), TypeError);
});

test('concurrent changes of one list are all kept (optimistic concurrency)', async () => {
  const { service, storage } = setup();
  const got = await Promise.all([1, 2, 3, 4].map(() => service.allocate('truong-mau')));
  await Promise.all(got.map((g) => service.setStatus('truong-mau', 1, g.idx, 'revoked')));
  for (const g of got) await assert.rejects(service.setStatus('truong-mau', 1, g.idx, 'valid'), StatusRevokedError);
  assert.equal((await storage.load('truong-mau', 1))?.version, 5);
});

test('token: null for a list that does not exist; n is bounded', async () => {
  const { service } = setup();
  assert.equal(await service.token('truong-mau', 1), null);
  assert.equal(await service.token('truong-mau', 999_999_999), null);
  await assert.rejects(service.token('truong-mau', 2 ** 53 - 1), TypeError);
  await assert.rejects(service.token('truong-mau', 0), TypeError);
  await service.allocate('truong-mau');
  assert.equal(typeof (await service.token('truong-mau', 1)), 'string');
});

test('iat strictly increases: same-second re-sign, clock step back, restart with the persisted lastIat', async () => {
  const { service, storage, clock } = setup(indexes(10, 11));
  await service.allocate('truong-mau');
  await service.allocate('truong-mau');
  const t1 = (await service.token('truong-mau', 1))!;
  await service.setStatus('truong-mau', 1, 10, 'revoked');
  const t2 = (await service.token('truong-mau', 1))!;
  assert.equal(iatOf(t2), iatOf(t1) + 1, 'same second: iat + 1');
  clock.advance(-30);
  await service.setStatus('truong-mau', 1, 11, 'suspended');
  const t3 = (await service.token('truong-mau', 1))!;
  assert.equal(iatOf(t3), iatOf(t2) + 1, 'clock stepped back');
  const restarted = createStatusListService({ issuerUri, keyStore, storage, random: webCryptoRandom, clock });
  assert.equal(iatOf((await restarted.token('truong-mau', 1))!), iatOf(t3) + 1, 'restart: from the stored lastIat');
});

test('the token verifies with the core verifier; re-signed on change and after one hour', async () => {
  const { service, clock } = setup(indexes(42));
  const trust = createTrustListService({ source: () => TRUST_CONTENT, keyStore, clock });
  const fetch: HttpFetch = async () => ({ status: 200, headers: { get: () => null }, text: () => trust.token() });
  const chainValidator = validatorFor(DEMO);
  const trustRegistry = createSignedTrustListRegistry({ url: 'https://api-identra.awncorp.vn/trust-list', fetch, verifier: webCryptoVerifier, chainValidator, clock, maxAgeSeconds: 0 });
  const read = async (token: string | null, issuer = 'VATVN-0100000001') => {
    const r = await verifyStatusListToken(token, { uri: URI(), issuer: { maToChuc: issuer }, chainValidator, trustRegistry, verifier: webCryptoVerifier, now: clock.now() });
    assert.ok(r.ok, r.ok ? '' : `${r.reason}: ${r.detail}`);
    return r;
  };

  await service.allocate('truong-mau');
  const t1 = (await service.token('truong-mau', 1))!;
  assert.equal((await read(t1)).list.getStatus(42), 0);
  assert.equal(await service.token('truong-mau', 1), t1, 'unchanged: the cached token');
  await service.setStatus('truong-mau', 1, 42, 'revoked');
  const t2 = (await service.token('truong-mau', 1))!;
  assert.notEqual(t2, t1);
  assert.equal((await read(t2)).list.getStatus(42), 1);
  clock.advance(3599);
  assert.equal(await service.token('truong-mau', 1), t2);
  clock.advance(1);
  const t3 = (await service.token('truong-mau', 1))!;
  assert.notEqual(t3, t2);
  assert.equal((await read(t3)).iat, Math.floor(clock.now().getTime() / 1000));
  // Signed with the status certificate of Truong Mau: not valid for another organisation's credentials.
  const other = await verifyStatusListToken(t3, { uri: URI(), issuer: { maToChuc: 'VATVN-0100000002' }, chainValidator, trustRegistry, verifier: webCryptoVerifier, now: clock.now() });
  assert.equal(other.ok, false);
});

test('setStatus with opts.storage does the whole update on that storage (the caller\'s transaction)', async () => {
  const shared = createMemoryStatusListStorage();
  const counting = (log: string[]): StatusListStorage => ({
    load: (...a) => (log.push('load'), shared.load(...a)),
    save: (...a) => (log.push('save'), shared.save(...a)),
    recordIat: (...a) => (log.push('recordIat'), shared.recordIat(...a)),
    reserve: (...a) => (log.push('reserve'), shared.reserve(...a)),
    isReserved: (...a) => (log.push('isReserved'), shared.isReserved(...a)),
  });
  const service: string[] = [];
  const tx: string[] = [];
  const s = createStatusListService({ issuerUri, keyStore, storage: counting(service), random: webCryptoRandom, clock: fakeClock() });
  const { n, idx } = await s.allocate('truong-mau');
  service.length = 0;
  await s.setStatus('truong-mau', n, idx, 'revoked', { storage: counting(tx) });
  assert.deepEqual(service, [], 'the service storage is not used');
  assert.deepEqual(tx, ['isReserved', 'load', 'save']);
  await s.setStatus('truong-mau', n, idx, 'revoked');
  assert.deepEqual(service, ['isReserved', 'load'], 'already revoked: read through the default storage, nothing saved');
});
