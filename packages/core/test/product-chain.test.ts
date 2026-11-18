// verifyProductChain (step 10, docs/architecture.md section 10) on the DEMO PKI with the real trust
// registry and status checker: complete and partial chains, every CHAIN_BROKEN rule with its event
// index, tampering, revocation, trust scopes, limits, and claim values passed through verbatim.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ErrorCodes, productEventHash, verifyProductChain, VCT, type ProductChainResult } from '@identra/sdk-core';
import { webCryptoHasher } from '@identra/sdk-core/webcrypto';
import { CODE, GTIN, ORGS, productWorld, SERIAL, statusUriOf, TIMES, trustIssuer } from './helpers/product.js';
import { TRUST_URL } from './helpers/lists.js';

const view = { gtin: GTIN, serial: SERIAL };
/** [index, code of product_chain] of every event. */
const links = (r: ProductChainResult) => r.events.map((e) => e.checks.find((c) => c.id === 'product_chain')!.code);
const failing = (r: ProductChainResult) => r.events.map((e) => e.checks.filter((c) => !c.ok).map((c) => `${c.id}:${c.code}`));
const count = (urls: string[], url: string) => urls.filter((u) => u === url).length;

async function run(events: unknown, world?: Awaited<ReturnType<typeof productWorld>>) {
  const w = world ?? (await productWorld());
  return verifyProductChain({ ...view, events }, w.options());
}

test('a complete chain of three organisations verifies; each list is fetched once', async () => {
  const w = await productWorld();
  const r = await verifyProductChain({ ...view, events: await w.chain(3) }, w.options());
  assert.deepEqual(failing(r), [[], [], []]);
  assert.deepEqual({ ok: r.ok, code: r.code, complete: r.complete }, { ok: true, code: null, complete: true });
  assert.deepEqual(r.events.map((e) => [e.index, e.event?.congDoan, e.event?.thoiDiem, e.event?.issuer?.ten]), [
    [0, 'san_xuat', TIMES[0], 'nha-san-xuat (DEMO)'],
    [1, 'kiem_dinh', TIMES[1], 'kiem-dinh (DEMO)'],
    [2, 'phan_phoi', TIMES[2], 'phan-phoi (DEMO)'],
  ]);
  assert.equal(r.events[0]!.event!.maSanPham, CODE);
  assert.deepEqual(r.events[0]!.checks.map((c) => c.id), ['structure', 'algorithm', 'certificate_chain', 'signature', 'validity_time', 'credential_type', 'issuer_trust', 'status', 'product_chain']);
  const urls = w.urls();
  assert.equal(count(urls, TRUST_URL), 1);
  for (const org of ORGS) assert.equal(count(urls, statusUriOf(org)), 1, org);
  assert.equal(urls.length, 4);
});

test('a partial chain (1 or 2 stages) is not an error: every event ok, complete false, code null', async () => {
  const w = await productWorld();
  for (const n of [1, 2]) {
    const r = await verifyProductChain({ ...view, events: await w.chain(n) }, w.options());
    assert.deepEqual({ ok: r.ok, code: r.code, complete: r.complete, events: r.events.map((e) => e.ok) }, { ok: false, code: null, complete: false, events: Array(n).fill(true) });
  }
});

test('CHAIN_BROKEN: each rule, at the index of the offending event', async () => {
  const w = await productWorld();
  const [e0, e1] = await w.chain(2);
  const full = await w.chain(3);
  const other = await w.issue(0, undefined, { ma_san_pham: `(01)${GTIN}(21)SN-0002` });
  const cases: [string, string[], (string | null)[]][] = [
    ['event of another product', [e0!, await w.issue(1, e0, { ma_san_pham: `(01)${GTIN}(21)SN-0002` })], [null, 'CHAIN_BROKEN']],
    ['first event of another product', [other], ['CHAIN_BROKEN']],
    ['wrong order', [e0!, await w.issue(2, e0, { cong_doan: 'phan_phoi' })], [null, 'CHAIN_BROKEN']],
    ['repeated stage', [e0!, await w.issue(1, e0, { cong_doan: 'san_xuat' }, 'nha-san-xuat')], [null, 'CHAIN_BROKEN']],
    ['missing first stage', [await w.issue(1, undefined)], ['CHAIN_BROKEN']],
    ['gap (no inspection)', [e0!, await w.issue(2, e0)], [null, 'CHAIN_BROKEN']],
    ['prev on the first event', [await w.issue(0, other)], ['CHAIN_BROKEN']],
    ['wrong prev', [e0!, await w.issue(1, other)], [null, 'CHAIN_BROKEN']],
    ['thoi_diem going backwards', [e0!, await w.issue(1, e0, { thoi_diem: '2026-01-02T07:59:59.999Z' })], [null, 'CHAIN_BROKEN']],
    ['thoi_diem not an ISO 8601 UTC instant', [e0!, await w.issue(1, e0, { thoi_diem: '2026-01-03' })], [null, 'CHAIN_BROKEN']],
    ['thoi_diem not a real date', [await w.issue(0, undefined, { thoi_diem: '2026-02-30T00:00:00Z' })], ['CHAIN_BROKEN']],
    ['a fourth event', [...full, await w.issue(2, full[2], {}, 'phan-phoi')], [null, null, null, 'CHAIN_BROKEN']],
    ['wrong vct', [e0!, await w.craft('kiem-dinh', { vct: VCT.diploma, ma_san_pham: CODE, cong_doan: 'kiem_dinh', thoi_diem: TIMES[1], dia_diem: 'd', mo_ta: 'm', prev: await productEventHash(e0!, webCryptoHasher) })], [null, 'CHAIN_BROKEN']],
  ];
  for (const [name, events, expected] of cases) {
    const r = await run(events, w);
    assert.deepEqual(links(r), expected, name);
    assert.equal(r.code, 'CHAIN_BROKEN', name);
    assert.equal(r.ok, false, name);
  }
  // Equal instants are allowed; and the link before a broken one is untouched.
  const same = await run([e0!, await w.issue(1, e0, { thoi_diem: TIMES[0]! })], w);
  assert.deepEqual(links(same), [null, null]);
  assert.deepEqual(links(await run([e0!, e1!], w)), [null, null]);
});

test('a wrong vct is also VCT_UNSUPPORTED and ISSUER_NOT_TRUSTED for that event', async () => {
  const w = await productWorld();
  const e = await w.craft('nha-san-xuat', { vct: VCT.diploma, ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: 'd', mo_ta: 'm' });
  assert.deepEqual(failing(await run([e], w)), [['credential_type:VCT_UNSUPPORTED', 'issuer_trust:ISSUER_NOT_TRUSTED', 'status:SKIPPED', 'product_chain:CHAIN_BROKEN']]);
});

test('one tampered byte in event 2: event 2 fails its own steps 1-4, event 3 is CHAIN_BROKEN, event 1 untouched', async () => {
  const w = await productWorld();
  const events = await w.chain(3);
  const [header, payload, signature] = events[1]!.slice(0, -1).split('.');
  const flip = (s: string, i: number) => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
  for (const tampered of [`${header}.${payload}.${flip(signature!, 10)}~`, `${header}.${flip(payload!, 40)}.${signature}~`]) {
    const r = await run([events[0], tampered, events[2]], w);
    assert.deepEqual(failing(r)[0], []);
    const step = r.events[1]!.checks.find((c) => !c.ok && !c.skipped)!;
    assert.ok(['signature:SIGNATURE_INVALID', 'structure:MALFORMED'].includes(`${step.id}:${step.code}`), `${step.id}:${step.code}`);
    assert.equal(r.events[1]!.checks.at(-1)!.code, 'SKIPPED');
    assert.equal(r.events[1]!.event, undefined);
    assert.deepEqual(failing(r)[2], ['product_chain:CHAIN_BROKEN']);
    assert.deepEqual({ ok: r.ok, code: r.code, complete: r.complete }, { ok: false, code: 'CHAIN_BROKEN', complete: false });
  }
});

test('a revoked or suspended event 2 is red at event 2 only; its successor still links', async () => {
  for (const [value, code] of [[1, 'REVOKED'], [2, 'SUSPENDED']] as const) {
    const w = await productWorld();
    w.setStatus('kiem-dinh', 11, value);
    await w.publish();
    const r = await verifyProductChain({ ...view, events: await w.chain(3) }, w.options());
    assert.deepEqual(failing(r), [[], [`status:${code}`], []]);
    assert.deepEqual({ ok: r.ok, code: r.code, complete: r.complete }, { ok: false, code: null, complete: true });
    assert.equal(r.events[1]!.event?.congDoan, 'kiem_dinh'); // still shown, with its red status
  }
});

test('an issuer absent from the trust list: ISSUER_NOT_TRUSTED, status SKIPPED, its status list never fetched', async () => {
  const w = await productWorld({ issuers: [trustIssuer('nha-san-xuat'), trustIssuer('kiem-dinh')] });
  const r = await verifyProductChain({ ...view, events: await w.chain(3) }, w.options());
  assert.deepEqual(failing(r), [[], [], ['issuer_trust:ISSUER_NOT_TRUSTED', 'status:SKIPPED']]);
  assert.equal(r.events[2]!.event!.issuer, null);
  assert.equal(count(w.urls(), statusUriOf('phan-phoi')), 0);
});

test('the manufacturer signing an inspection event is caught by issuer_trust (cong_doan scope)', async () => {
  const w = await productWorld();
  const [e0] = await w.chain(1);
  const r = await run([e0, await w.issue(1, e0, {}, 'nha-san-xuat')], w);
  assert.deepEqual(failing(r), [[], ['issuer_trust:ISSUER_NOT_TRUSTED', 'status:SKIPPED']]);
  // With the inspection scope added to the manufacturer's entry, the same event passes.
  const widened = await productWorld({ issuers: [trustIssuer('nha-san-xuat', ['san_xuat', 'kiem_dinh'])] });
  assert.deepEqual(failing(await run([e0, await widened.issue(1, e0, {}, 'nha-san-xuat')], widened)), [[], []]);
});

test('21 events: TOO_LARGE before anything is verified or fetched (ADR-0012 requirement 4)', async () => {
  const w = await productWorld();
  const [e0] = await w.chain(1);
  let hashes = 0;
  const options = { ...w.options(), hasher: { sha256: (d: Uint8Array) => (hashes++, webCryptoHasher.sha256(d)) } };
  const r = await verifyProductChain({ ...view, events: Array(21).fill(e0) }, options);
  assert.deepEqual(r, { ok: false, code: 'TOO_LARGE', complete: false, events: [] });
  assert.equal(hashes, 0);
  assert.deepEqual(w.urls(), []);
  assert.equal((await verifyProductChain({ ...view, events: Array(20).fill('x'.repeat(16_385)) }, options)).code, 'TOO_LARGE'); // total bound
});

test('a list that is not an array of strings, or empty, is MALFORMED', async () => {
  for (const events of [undefined, null, 'x', {}, [], [1], ['a', null], Array(2), [, 'a']]) assert.equal((await run(events)).code, ErrorCodes.MALFORMED);
  const w = await productWorld();
  await assert.rejects(verifyProductChain({ gtin: '09520123456789', serial: SERIAL, events: [] }, w.options()), TypeError);
});

test('HTML in claims comes back verbatim as plain strings; the 500-character cap holds at issuance and verification', async () => {
  const w = await productWorld();
  const script = '<script>alert(1)</script>';
  const img = '<img src=x onerror=alert(document.cookie)>';
  const e0 = await w.issue(0, undefined, { mo_ta: script, dia_diem: img });
  const r = await run([e0], w);
  assert.equal(r.events[0]!.ok, true);
  assert.equal(r.events[0]!.event!.moTa, script);
  assert.equal(r.events[0]!.event!.diaDiem, img);
  await assert.rejects(w.issue(0, undefined, { mo_ta: 'x'.repeat(501) }), /at most 500 characters/);
  assert.equal(typeof (await w.issue(0, undefined, { mo_ta: 'x'.repeat(500) })), 'string');
  // A foreign issuer bypassing issueProductEvent: the event fails and its values are not handed out.
  const long = await w.craft('nha-san-xuat', { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: 'd', mo_ta: 'x'.repeat(501) });
  const bad = await run([long], w);
  assert.deepEqual(failing(bad), [['product_chain:MALFORMED']]);
  assert.equal(bad.events[0]!.event, undefined);
  assert.equal(bad.code, 'CHAIN_BROKEN');
  const nonString = await w.craft('nha-san-xuat', { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: { html: img }, mo_ta: 'm' });
  assert.deepEqual(failing(await run([nonString], w)), [['product_chain:MALFORMED']]);
});

test('status lists unreachable: STATUS_UNAVAILABLE on every event; trust list unreachable: TRUST_LIST_UNAVAILABLE', async () => {
  const w = await productWorld();
  const events = await w.chain(3);
  for (const org of ORGS) w.served.routes[statusUriOf(org)] = new Error('down');
  assert.deepEqual(failing(await run(events, w)), Array(3).fill(['status:STATUS_UNAVAILABLE']));
  w.served.routes[TRUST_URL] = new Error('down');
  const r = await run(events, w);
  assert.deepEqual(failing(r), Array(3).fill(['issuer_trust:TRUST_LIST_UNAVAILABLE', 'status:SKIPPED']));
  assert.equal(r.code, null);
});
