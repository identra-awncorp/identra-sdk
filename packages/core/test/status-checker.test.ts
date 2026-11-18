// createStatusListChecker: fail-closed answers and the caching rules of docs/architecture.md
// section 5, with a fake clock and a scripted fetch whose calls are counted in every scenario.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { createSignedTrustListRegistry, createStatusList, createStatusListChecker, createStatusListToken, type StatusValue } from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { NOW } from './helpers/pki.js';
import { demoContent, fakeClock, ok, ORG, otherOrgStatus, scriptedFetch, statusSigner, TRUST_URL, trustToken, type Route } from './helpers/lists.js';
import { ISS, validator } from './helpers/sdjwt.js';

const URI = `${ISS}/status/1`;
const ISSUER = { maToChuc: ORG.truongMau };
const signer = await statusSigner();
const trust = await trustToken(undefined, NOW, { lifetimeSeconds: 7 * 86_400 });

async function token(statuses: Record<number, StatusValue> = {}, o: { at?: Date; lifetimeSeconds?: number; uri?: string; signer?: typeof signer } = {}) {
  const list = createStatusList();
  for (const [i, v] of Object.entries(statuses)) list.setStatus(Number(i), v);
  return createStatusListToken({ list, uri: o.uri ?? URI, signer: o.signer ?? signer, now: o.at ?? NOW, ...(o.lifetimeSeconds ? { lifetimeSeconds: o.lifetimeSeconds } : {}) });
}

function world(routes: Record<string, Route | (() => Route | Promise<Route>)>, o: { maxAgeSeconds?: number; trustRoute?: () => Route; trustMaxAge?: number } = {}) {
  const clock = fakeClock();
  const t = scriptedFetch({ [TRUST_URL]: o.trustRoute ?? ok(trust) });
  const trustRegistry = createSignedTrustListRegistry({
    url: TRUST_URL, fetch: t.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock, ...(o.trustMaxAge !== undefined ? { maxAgeSeconds: o.trustMaxAge } : {}),
  });
  const s = scriptedFetch(routes);
  const checker = createStatusListChecker({
    fetch: s.fetch, verifier: webCryptoVerifier, chainValidator: validator, trustRegistry, clock, ...(o.maxAgeSeconds !== undefined ? { maxAgeSeconds: o.maxAgeSeconds } : {}),
  });
  const check = (idx = 42, uri = URI, issuer = ISSUER) => checker.check({ uri, idx }, issuer);
  return { clock, check, calls: s.calls, routes: s.routes };
}

describe('answers', () => {
  test('valid, revoked, suspended; one fetch with the 5 s timeout', async () => {
    const w = world({ [URI]: ok(await token({ 42: 1, 43: 2 })) });
    assert.deepEqual([await w.check(41), await w.check(42), await w.check(43)], ['valid', 'revoked', 'suspended']);
    assert.deepEqual(w.calls, [{ url: URI, timeoutMs: 5000 }]);
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
    w.routes[URI] = ok(await token({ 42: 1 }));
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
  test('at most 100 uris are held; the oldest is evicted', async () => {
    const uri = (n: number) => `${ISS}/status/${n}`;
    const routes: Record<string, Route> = {};
    for (let n = 1; n <= 101; n++) routes[uri(n)] = ok(await token({}, { uri: uri(n) }));
    const w = world(routes);
    for (let n = 1; n <= 101; n++) assert.equal(await w.check(0, uri(n)), 'valid');
    assert.equal(w.calls.length, 101);
    await w.check(0, uri(101));
    await w.check(0, uri(2));
    assert.equal(w.calls.length, 101, 'the 100 newest are held');
    await w.check(0, uri(1));
    assert.equal(w.calls.length, 102, 'the oldest was evicted');
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
