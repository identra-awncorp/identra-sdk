// createProductVerifier against a node:http listener standing in for the canonical API: a verified
// chain, every failure state, and a recording fetch proving which requests are made (ADR-0012
// security requirement 3) and how (no redirect, cookies, referrer or HTTP cache).
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createProductVerifier } from '@identra/sdk-client/product';
import { CANONICAL, eventsPath, helpers, json, serve, type World } from './product-world.js';

const { GTIN, SERIAL, CODE, TIMES } = helpers;
const server = await serve(47660);
after(server.close);

const SERVER_TIME = '2026-11-18T10:00:00Z';
const NO_SERVER_TIME = Symbol('absent');

function setup(world: World, events: string[], serverTime: unknown = SERVER_TIME) {
  server.state.world = world;
  server.state.handlers = { [eventsPath()]: json(200, { gtin: GTIN, serial: SERIAL, events, ...(serverTime === NO_SERVER_TIME ? {} : { serverTime }) }) };
  server.state.requests = [];
  const calls: { url: string; init: RequestInit }[] = [];
  const recording: typeof fetch = (input, init = {}) => {
    calls.push({ url: String(input), init });
    return fetch(input, init);
  };
  const verifier = createProductVerifier({ apiBaseUrl: server.baseUrl, rootCertificates: [world.root], fetch: recording, now: () => world.now.getTime() });
  return { verifier, calls, paths: () => calls.map((c) => c.url.slice(server.baseUrl.length)) };
}

test('a complete chain loads and verifies; requests: events, trust list, one status list per issuer', async () => {
  const world = await helpers.productWorld();
  const { verifier, calls, paths } = setup(world, await world.chain(3));
  const view = await verifier.load(GTIN, SERIAL);
  assert.equal(view.state, 'ok');
  assert.deepEqual({ state: view.result!.state, ok: view.result!.ok, complete: view.result!.complete, code: view.result!.code }, { state: 'verified', ok: true, complete: true, code: null });
  assert.deepEqual(view.result!.events.map((e) => e.event?.thoiDiem), TIMES);
  assert.equal(view.result!.events[0]!.event!.maSanPham, CODE);
  assert.equal(view.verifiedAt, world.now.toISOString());
  assert.equal(view.serverTime, SERVER_TIME);
  assert.equal(view.clockSkewSeconds, Math.round((world.now.getTime() - Date.parse(SERVER_TIME)) / 1000));
  const status = (org: string) => helpers.statusUriOf(org).slice(CANONICAL.length);
  assert.deepEqual(paths(), [eventsPath(), '/trust-list', status('nha-san-xuat'), status('kiem-dinh'), status('phan-phoi')]);
  for (const { init } of calls) {
    assert.deepEqual([init.redirect, init.credentials, init.referrerPolicy, init.cache], ['error', 'omit', 'no-referrer', 'no-store']);
    assert.ok(init.signal instanceof AbortSignal);
  }
});

test('an issuer outside the trust list: the only requests are the events and the trust list', async () => {
  const world = await helpers.productWorld({ issuers: [] });
  const { verifier, paths } = setup(world, await world.chain(3));
  const view = await verifier.load(GTIN, SERIAL);
  assert.deepEqual(view.result!.events.map((e) => e.checks.filter((c) => !c.ok).map((c) => c.code)), Array(3).fill(['ISSUER_NOT_TRUSTED', 'SKIPPED']));
  assert.deepEqual(paths(), [eventsPath(), '/trust-list']);
  assert.deepEqual(server.state.requests, [eventsPath(), '/trust-list']);
});

test('a credential pointing its status at another host never causes a request there', async () => {
  const world = await helpers.productWorld();
  const event = await world.craft('nha-san-xuat', {
    ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: 'd', mo_ta: 'm',
    status: { status_list: { idx: 1, uri: 'https://evil.example/issuers/nha-san-xuat/status/1' } },
  });
  const { verifier, calls } = setup(world, [event]);
  const view = await verifier.load(GTIN, SERIAL);
  assert.equal(view.result!.events[0]!.checks.find((c) => c.id === 'status')!.code, 'STATUS_UNAVAILABLE');
  assert.ok(calls.every((c) => c.url.startsWith(server.baseUrl)), 'every request went to the configured API');
  assert.deepEqual(calls.map((c) => c.url.slice(server.baseUrl.length)), [eventsPath(), '/trust-list']);
});

test('failure states: 404, server error, malformed JSON, wrong shape, echo mismatch, oversized, slow', async (t) => {
  const world = await helpers.productWorld();
  const [e0] = await world.chain(1);
  const cases: [string, unknown, number, string][] = [
    ['unknown product', { statusCode: 404 }, 404, 'not_found'],
    ['server error', {}, 500, 'network_error'],
    ['not JSON', '{"gtin":', 200, 'invalid_response'],
    ['not an object', [e0], 200, 'invalid_response'],
    ['events not an array', { gtin: GTIN, serial: SERIAL, events: e0 }, 200, 'invalid_response'],
    ['gtin not echoed', { gtin: '09520123456795', serial: SERIAL, events: [e0] }, 200, 'invalid_response'],
    ['serial not echoed', { gtin: GTIN, serial: 'SN-0002', events: [e0] }, 200, 'invalid_response'],
    ['oversized body', { gtin: GTIN, serial: SERIAL, events: Array(21).fill('x'.repeat(16_384)) }, 200, 'invalid_response'],
  ];
  for (const [name, body, status, state] of cases) {
    const { verifier } = setup(world, []);
    server.state.handlers[eventsPath()] = json(status, body);
    assert.equal((await verifier.load(GTIN, SERIAL)).state, state, name);
  }
  // Oversized without a Content-Length: the stream is cut once it passes the cap.
  const { verifier } = setup(world, []);
  server.state.handlers[eventsPath()] = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    for (let i = 0; i < 40; i++) res.write('x'.repeat(16_384));
    res.end();
  };
  assert.equal((await verifier.load(GTIN, SERIAL)).state, 'invalid_response', 'chunked oversized');
  // A list the server returns empty or with 21 entries is verified by the SDK: MALFORMED / TOO_LARGE.
  server.state.handlers[eventsPath()] = json(200, { gtin: GTIN, serial: SERIAL, events: [] });
  assert.equal((await verifier.load(GTIN, SERIAL)).result?.code, 'MALFORMED');
  server.state.handlers[eventsPath()] = json(200, { gtin: GTIN, serial: SERIAL, events: Array(21).fill(e0) });
  assert.equal((await verifier.load(GTIN, SERIAL)).result?.code, 'TOO_LARGE');
  // Slow: headers never come; the 5 s timeout ends the load.
  server.state.handlers[eventsPath()] = () => {};
  const started = Date.now();
  assert.equal((await verifier.load(GTIN, SERIAL)).state, 'network_error', 'slow');
  t.diagnostic(`timed out after ${Date.now() - started} ms`);
  assert.ok(Date.now() - started < 7000);
  // A redirect is refused, not followed.
  server.state.handlers[eventsPath()] = (_req, res) => void res.writeHead(302, { location: 'https://evil.example/' }).end();
  assert.equal((await verifier.load(GTIN, SERIAL)).state, 'network_error', 'redirect');
});

test('serials are percent-encoded in the API path; invalid input is a programmer error', async () => {
  const world = await helpers.productWorld();
  const { verifier, paths } = setup(world, []);
  assert.equal((await verifier.load(GTIN, 'A/B?')).state, 'not_found');
  assert.deepEqual(paths(), [`/v1/products/${GTIN}/A%2FB%3F/events`]);
  await assert.rejects(verifier.load('09520123456789', SERIAL), TypeError);
  await assert.rejects(verifier.load(GTIN, '..'), TypeError);
  assert.throws(() => createProductVerifier({ apiBaseUrl: 'http://127.0.0.1:1/path', rootCertificates: [world.root] }), TypeError);
});

test('a trusted certificate whose SAN is on another host: its status list is never requested there', async () => {
  const foreign = await helpers.foreignSanIssuer('https://evil.example/issuers/nha-san-xuat');
  const world = await helpers.productWorld({ issuers: [foreign.entry, helpers.trustIssuer('kiem-dinh'), helpers.trustIssuer('phan-phoi')] });
  const { verifier, calls, paths } = setup(world, [foreign.event]);
  const view = await verifier.load(GTIN, SERIAL);
  const failed = view.result!.events[0]!.checks.filter((c) => !c.ok).map((c) => `${c.id}:${c.code}`);
  assert.deepEqual(failed, ['status:STATUS_UNAVAILABLE']); // chain and trust pass: only the pinned fetch stops it
  assert.ok(calls.every((c) => c.url.startsWith(server.baseUrl)), calls.map((c) => c.url).join(' '));
  assert.deepEqual(paths(), [eventsPath(), '/trust-list']);
});

test('F5-1: a trusted SAN on the API origin with a dot segment or an escaped one reaches no other path', async () => {
  for (const iss of [`${CANONICAL}/issuers/x/../../v1/admin`, `${CANONICAL}/issuers/x/%2e%2e/%2e%2e/v1/admin`, `${CANONICAL}/issuers/X`, `${CANONICAL}/issuers/a?b`]) {
    const foreign = await helpers.foreignSanIssuer(iss);
    const world = await helpers.productWorld({ issuers: [foreign.entry, helpers.trustIssuer('kiem-dinh'), helpers.trustIssuer('phan-phoi')] });
    const { verifier, paths } = setup(world, [foreign.event]);
    const view = await verifier.load(GTIN, SERIAL);
    assert.deepEqual(view.result!.events[0]!.checks.filter((c) => !c.ok).map((c) => `${c.id}:${c.code}`), ['status:STATUS_UNAVAILABLE'], iss);
    assert.deepEqual(paths(), [eventsPath(), '/trust-list'], iss);
  }
});

test('serverTime is a hint only: validated strictly, and a lying one changes no check', async () => {
  const world = await helpers.productWorld();
  const events = await world.chain(3);
  const honest = await setup(world, events).verifier.load(GTIN, SERIAL);
  for (const lie of ['2000-01-01T00:00:00Z', '9999-12-31T23:59:59.999Z']) {
    const view = await setup(world, events, lie).verifier.load(GTIN, SERIAL);
    assert.deepEqual(view.result, honest.result, lie);
    assert.equal(view.serverTime, lie);
    assert.equal(view.clockSkewSeconds, Math.round((world.now.getTime() - Date.parse(lie)) / 1000));
  }
  const absent = await setup(world, events, NO_SERVER_TIME).verifier.load(GTIN, SERIAL);
  assert.deepEqual([absent.state, absent.serverTime, absent.clockSkewSeconds], ['ok', undefined, undefined]);
  for (const bad of ['tomorrow', 0, null, '2026-11-18T10:00:00+07:00', '2026-02-30T00:00:00Z', 'Wed, 18 Nov 2026 10:00:00 GMT']) {
    assert.equal((await setup(world, events, bad).verifier.load(GTIN, SERIAL)).state, 'invalid_response', String(bad));
  }
});
