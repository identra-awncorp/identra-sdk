// createStatusListChecker: fail-closed answers and the caching rules of docs/architecture.md
// section 5, with a fake clock and a scripted fetch whose calls are counted in every scenario.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createSignedTrustListRegistry, createStatusList, createStatusListChecker, createStatusListToken, type SeenStore, type StatusValue } from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { NOW } from './helpers/pki.js';
import { demoContent, fakeClock, ok, ORG, otherOrgStatus, scriptedFetch, statusSigner, TRUST_URL, trustToken, type Route } from './helpers/lists.js';
import { ISS, NOW_S, rawJws, validator } from './helpers/sdjwt.js';

const URI = `${ISS}/status/1`;
const ISSUER = { maToChuc: ORG.truongMau };
const signer = await statusSigner();
const trust = await trustToken(undefined, NOW);

async function token(statuses: Record<number, StatusValue> = {}, o: { at?: Date; lifetimeSeconds?: number; uri?: string; signer?: typeof signer } = {}) {
  const list = createStatusList();
  for (const [i, v] of Object.entries(statuses)) list.setStatus(Number(i), v);
  return createStatusListToken({ list, uri: o.uri ?? URI, signer: o.signer ?? signer, now: o.at ?? NOW, ...(o.lifetimeSeconds ? { lifetimeSeconds: o.lifetimeSeconds } : {}) });
}

function world(routes: Record<string, Route | (() => Route | Promise<Route>)>, o: { maxAgeSeconds?: number; trustRoute?: () => Route; trustMaxAge?: number; seen?: SeenStore; clock?: ReturnType<typeof fakeClock> } = {}) {
  const clock = o.clock ?? fakeClock();
  const t = scriptedFetch({ [TRUST_URL]: o.trustRoute ?? ok(trust) });
  const trustRegistry = createSignedTrustListRegistry({
    url: TRUST_URL, fetch: t.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock, ...(o.trustMaxAge !== undefined ? { maxAgeSeconds: o.trustMaxAge } : {}),
  });
  const s = scriptedFetch(routes);
  const checker = createStatusListChecker({
    fetch: s.fetch, verifier: webCryptoVerifier, chainValidator: validator, trustRegistry, clock,
    ...(o.maxAgeSeconds !== undefined ? { maxAgeSeconds: o.maxAgeSeconds } : {}), ...(o.seen ? { seen: o.seen } : {}),
  });
  const check = (idx = 42, uri = URI, issuer = ISSUER) => checker.check({ uri, idx }, issuer);
  return { clock, check, calls: s.calls, routes: s.routes };
}

describe('answers', () => {
  test('valid, revoked, suspended; one fetch with the 5 s timeout', async () => {
    const w = world({ [URI]: ok(await token({ 42: 1, 43: 2 })) });
    assert.deepEqual([await w.check(41), await w.check(42), await w.check(43)], ['valid', 'revoked', 'suspended']);
    assert.deepEqual(w.calls, [{ url: URI, timeoutMs: 5000, maxBytes: 131_072 }]);
  });
  test('refused before any fetch: non-https uri, idx out of range, no issuer organisation', async () => {
    const w = world({ [URI]: ok(await token()) });
    assert.equal(await w.check(0, 'http://api-identra.awncorp.vn/issuers/truong-mau/status/1'), 'unavailable');
    for (const idx of [-1, 131_072, 1.5]) assert.equal(await w.check(idx), 'unavailable');
    assert.equal(await w.check(0, URI, { maToChuc: '' }), 'unavailable');
    assert.equal(w.calls.length, 0);
  });
  test('HTTP 404 / 500 / timeout / oversize / not a token, without a held copy: unavailable after one fetch each', async () => {
    const answers: Route[] = [{ status: 404, body: '' }, { status: 500, body: await token() }, new Error('timeout after 5000 ms'), ok('a'.repeat(128 * 1024 + 1)), ok('nonsense'), { status: 201, body: await token() }];
    for (const a of answers) {
      const w = world({ [URI]: a });
      assert.equal(await w.check(), 'unavailable');
      assert.equal(w.calls.length, 1);
    }
  });
  test('a list signed by another organisation is unavailable', async () => {
    const w = world({ [URI]: ok(await token({}, { signer: (await otherOrgStatus()).signer })) });
    assert.equal(await w.check(), 'unavailable');
  });
});

describe('cache', () => {
  test('a fresh copy is used without refetch; refetch after ttl (900 s)', async () => {
    const w = world({ [URI]: ok(await token()) });
    await w.check();
    w.clock.advance(899);
    assert.equal(await w.check(), 'valid');
    assert.equal(w.calls.length, 1);
    w.clock.advance(1);
    w.routes[URI] = ok(await token({ 42: 1 }, { at: w.clock.now() }));
    assert.equal(await w.check(), 'revoked');
    assert.equal(w.calls.length, 2);
  });
  test('maxAgeSeconds bounds the age below ttl', async () => {
    const w = world({ [URI]: ok(await token()) }, { maxAgeSeconds: 60 });
    await w.check();
    w.clock.advance(59);
    await w.check();
    assert.equal(w.calls.length, 1);
    w.clock.advance(1);
    await w.check();
    assert.equal(w.calls.length, 2);
  });
  test('maxAgeSeconds 0 refetches every time, so a revocation is seen at once', async () => {
    const w = world({ [URI]: ok(await token()) }, { maxAgeSeconds: 0 });
    assert.equal(await w.check(), 'valid');
    // A new list always has a greater iat (ADR-0019 section 4), even within the same second.
    w.routes[URI] = ok(await token({ 42: 1 }, { at: new Date(NOW.getTime() + 1000) }));
    assert.equal(await w.check(), 'revoked');
    assert.equal(w.calls.length, 2);
  });
  test('refetch failure: the held copy is used until its exp (+60 s skew), then unavailable', async () => {
    const w = world({ [URI]: ok(await token({}, { lifetimeSeconds: 3600 })) });
    assert.equal(await w.check(), 'valid');
    w.routes[URI] = { status: 500, body: '' };
    w.clock.advance(1000);
    assert.equal(await w.check(), 'valid');
    w.clock.advance(3659 - 1000);
    assert.equal(await w.check(), 'valid');
    assert.equal(w.calls.length, 3, 'every read past ttl tries again');
    w.clock.advance(1);
    assert.equal(await w.check(), 'unavailable');
    assert.equal(w.calls.length, 4);
  });
  test('an invalid new token keeps the held copy', async () => {
    const w = world({ [URI]: ok(await token()) });
    await w.check();
    w.routes[URI] = ok(await token({ 42: 1 }, { signer: (await otherOrgStatus()).signer, at: NOW }));
    w.clock.advance(900);
    assert.equal(await w.check(), 'valid');
    assert.equal(w.calls.length, 2);
  });
  test('a copy whose iat is older than the held one is refused', async () => {
    const w = world({ [URI]: ok(await token({}, { at: new Date(NOW.getTime() + 30_000) })) });
    assert.equal(await w.check(), 'valid');
    w.routes[URI] = ok(await token({ 42: 1 }, { at: NOW }));
    w.clock.advance(900);
    assert.equal(await w.check(), 'valid');
    assert.equal(w.calls.length, 2);
    w.routes[URI] = ok(await token({ 42: 1 }, { at: w.clock.now() }));
    w.clock.advance(900);
    assert.equal(await w.check(), 'revoked', 'a newer copy replaces it');
  });
  test('concurrent checks of one uri share one in-flight fetch', async () => {
    const body = await token({ 42: 2 });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const w = world({ [URI]: async () => (await gate, ok(body)) });
    const pending = Promise.all([1, 2, 3, 4, 5].map(() => w.check()));
    await new Promise((r) => setTimeout(r, 10));
    release();
    assert.deepEqual(await pending, Array(5).fill('suspended'));
    assert.equal(w.calls.length, 1);
  });
  test('at most 100 uris are held; an unexpired one is never evicted to make room', async () => {
    const uri = (n: number) => `${ISS}/status/${n}`;
    const routes: Record<string, Route> = {};
    for (let n = 1; n <= 101; n++) routes[uri(n)] = ok(await token({}, { uri: uri(n), lifetimeSeconds: 3600 }));
    const w = world(routes);
    for (let n = 1; n <= 101; n++) assert.equal(await w.check(0, uri(n)), 'valid');
    assert.equal(w.calls.length, 101);
    await w.check(0, uri(101));
    assert.equal(w.calls.length, 102, 'the 101st was verified and used but not cached');
    await w.check(0, uri(1));
    await w.check(0, uri(100));
    assert.equal(w.calls.length, 102, 'the first 100 stay held');
    // Once they have expired, they make room.
    w.clock.advance(3661);
    w.routes[uri(101)] = ok(await token({}, { uri: uri(101), at: w.clock.now() }));
    await w.check(0, uri(101));
    await w.check(0, uri(101));
    assert.equal(w.calls.length, 103, 'now cached');
  });
  test('a held list whose signer has left the trust list is no longer used', async () => {
    const content = await demoContent();
    let trustBody = await trustToken(content, NOW);
    const w = world({ [URI]: ok(await token()) }, { trustMaxAge: 0, trustRoute: () => ok(trustBody) });
    assert.equal(await w.check(), 'valid');
    content.issuers[0]!.chung_thu = content.issuers[0]!.chung_thu.filter((c) => c.muc_dich !== 'status');
    w.clock.advance(1);
    trustBody = await trustToken(content, w.clock.now());
    assert.equal(await w.check(), 'unavailable');
    assert.equal(w.calls.length, 1, 'the status list itself was not refetched');
  });
});

describe('ADR-0019 caps and rollback rules', () => {
  test('D1: a status list living longer than 24 h (ttl 2^52, exp +10 y) is refused', async () => {
    const huge = await rawJws({ alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c }, { sub: URI, iat: NOW_S, exp: NOW_S + 10 * 365 * 86_400, ttl: 2 ** 52, status_list: createStatusList().encode() }, signer);
    const w = world({ [URI]: ok(huge) });
    assert.equal(await w.check(), 'unavailable');
    const edge = (life: number) => rawJws({ alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c }, { sub: URI, iat: NOW_S, exp: NOW_S + life, ttl: 900, status_list: createStatusList().encode() }, signer);
    assert.equal(await world({ [URI]: ok(await edge(86_460)) }).check(), 'valid', '24 h + 60 s skew is accepted');
    assert.equal(await world({ [URI]: ok(await edge(86_461)) }).check(), 'unavailable');
  });
  test('ttl 2^52 within 24 h, or no ttl: fresh for at most 900 s, so a revocation arrives', async () => {
    for (const ttl of [2 ** 52, undefined]) {
      const t = await rawJws({ alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c }, { sub: URI, iat: NOW_S, exp: NOW_S + 86_400, ttl, status_list: createStatusList().encode() }, signer);
      const w = world({ [URI]: ok(t) });
      assert.equal(await w.check(), 'valid');
      w.clock.advance(899);
      assert.equal(await w.check(), 'valid');
      assert.equal(w.calls.length, 1);
      w.clock.advance(1);
      w.routes[URI] = ok(await token({ 42: 1 }, { at: w.clock.now() }));
      assert.equal(await w.check(), 'revoked', `ttl ${ttl}`);
    }
  });
  test('equal iat: another token is refused, the identical token is accepted', async () => {
    const before = await token({}, { at: NOW });
    const after = await token({ 42: 1 }, { at: new Date(NOW.getTime() + 999) }); // same second
    const w = world({ [URI]: ok(after) });
    assert.equal(await w.check(), 'revoked');
    w.routes[URI] = ok(before);
    w.clock.advance(900);
    assert.equal(await w.check(), 'revoked', 'the pre-revocation list with the same iat is refused');
    w.routes[URI] = ok(after);
    w.clock.advance(900);
    assert.equal(await w.check(), 'revoked');
    assert.equal(await w.check(), 'revoked');
    assert.equal(w.calls.length, 3, 'the identical token refreshed the held copy');
  });
  test('a clock stepping back before the fetch makes the held copy stale', async () => {
    const clock = fakeClock(new Date(NOW.getTime() + 3600_000));
    const w = world({ [URI]: ok(await token({}, { at: clock.now() })) }, { clock });
    await w.check();
    clock.advance(-120);
    await w.check();
    assert.equal(w.calls.length, 2);
  });
  test('seen: the last accepted iat survives a restart', async () => {
    const store = new Map<string, number>();
    const seen: SeenStore = { get: async (k) => store.get(k) ?? null, set: async (k, v) => void store.set(k, v) };
    const newer = await token({ 42: 1 }, { at: new Date(NOW.getTime() + 30_000) });
    const first = world({ [URI]: ok(newer) }, { seen });
    assert.equal(await first.check(), 'revoked');
    assert.deepEqual([...store], [[`iat:${URI}`, NOW_S + 30]]);
    const restarted = world({ [URI]: ok(await token({}, { at: NOW })) }, { seen });
    assert.equal(await restarted.check(), 'unavailable', 'the older pre-revocation list is refused after a restart');
    const same = world({ [URI]: ok(newer) }, { seen });
    assert.equal(await same.check(), 'revoked', 'an equal iat is accepted on a cold start');
    const failing: SeenStore = { get: async () => { throw new Error('disk'); }, set: async () => { throw new Error('disk'); } };
    assert.equal(await world({ [URI]: ok(newer) }, { seen: failing }).check(), 'revoked', 'a failing store is treated as empty');
  });
});
