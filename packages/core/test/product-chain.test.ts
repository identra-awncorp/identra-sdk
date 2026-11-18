// verifyProductChain (step 10, docs/architecture.md section 10) on the DEMO PKI with the real trust
// registry and status checker: the verdict (verified / in_progress / failed), every CHAIN_BROKEN rule
// with its event index, tampering, revocation, trust scopes, limits, which events are shown, and
// claim values passed through verbatim.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ErrorCodes, productEventHash, verifyProductChain, VCT, type ProductChainResult } from '@identra/sdk-core';
import { webCryptoHasher } from '@identra/sdk-core/webcrypto';
import { parseCertificate } from '@identra/sdk-core';
import { CODE, demoCerts, demoSigner, GTIN, issOf, ORGS, productWorld, SERIAL, statusUriOf, TIMES, trustIssuer } from './helpers/product.js';
import { TRUST_URL } from './helpers/lists.js';
import { fingerprintOf, rawJws } from './helpers/sdjwt.js';

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
  assert.deepEqual({ state: r.state, ok: r.ok, code: r.code, complete: r.complete, missingStages: r.missingStages }, { state: 'verified', ok: true, code: null, complete: true, missingStages: [] });
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

test('a legitimate prefix (1 or 2 stages) is in_progress, with the stages still to come', async () => {
  const w = await productWorld();
  for (const [n, missing] of [[1, ['kiem_dinh', 'phan_phoi']], [2, ['phan_phoi']]] as const) {
    const r = await verifyProductChain({ ...view, events: await w.chain(n) }, w.options());
    assert.deepEqual(
      { state: r.state, ok: r.ok, code: r.code, complete: r.complete, missingStages: r.missingStages, events: r.events.map((e) => e.ok) },
      { state: 'in_progress', ok: false, code: null, complete: false, missingStages: missing, events: Array(n).fill(true) },
    );
    assert.ok(r.events.every((e) => e.event !== undefined));
  }
});

test('a bad last step is failed, never in_progress: forged stage, untrusted, tampered, garbage', async () => {
  const w = await productWorld();
  const [e0, e1] = await w.chain(2);
  const real = (await w.chain(3))[2]!;
  const tampered = real.slice(0, -12) + (real.at(-12) === 'A' ? 'B' : 'A') + real.slice(-11);
  const removed = await productWorld({ issuers: [trustIssuer('nha-san-xuat'), trustIssuer('kiem-dinh')] }); // phan-phoi left the trust list
  const cases: [string, string, Awaited<ReturnType<typeof productWorld>>, string][] = [
    ['manufacturer signs phan_phoi', await w.issue(2, e1, {}, 'nha-san-xuat'), w, 'ISSUER_NOT_TRUSTED'],
    ['untrusted last event', await removed.issue(2, e1), removed, 'ISSUER_NOT_TRUSTED'],
    ['tampered last event', tampered, w, 'SIGNATURE_INVALID'],
    ['garbage last event', 'garbage~', w, 'MALFORMED'],
  ];
  for (const [name, last, world, code] of cases) {
    const r = await run([e0, e1, last], world);
    assert.deepEqual({ state: r.state, ok: r.ok, complete: r.complete, code: r.code, missingStages: r.missingStages }, { state: 'failed', ok: false, complete: false, code, missingStages: [] }, name);
    assert.deepEqual(r.events.map((e) => e.ok), [true, true, false], name);
    assert.equal(r.events[2]!.event, undefined, `${name}: not shown`);
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
    // The issuer refuses these two, so a foreign issuer signs them directly.
    ['thoi_diem not an ISO 8601 UTC instant', [e0!, await w.craft('kiem-dinh', { ma_san_pham: CODE, cong_doan: 'kiem_dinh', thoi_diem: '2026-01-03', dia_diem: 'd', mo_ta: 'm', prev: await productEventHash(e0!, webCryptoHasher) })], [null, 'CHAIN_BROKEN']],
    ['thoi_diem not a real date', [await w.craft('nha-san-xuat', { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: '2026-02-30T00:00:00Z', dia_diem: 'd', mo_ta: 'm' })], ['CHAIN_BROKEN']],
    ['a fourth event', [...full, await w.issue(2, full[2], {}, 'phan-phoi')], [null, null, null, 'CHAIN_BROKEN']],
    ['wrong vct', [e0!, await w.craft('kiem-dinh', { vct: VCT.diploma, ma_san_pham: CODE, cong_doan: 'kiem_dinh', thoi_diem: TIMES[1], dia_diem: 'd', mo_ta: 'm', prev: await productEventHash(e0!, webCryptoHasher) })], [null, 'CHAIN_BROKEN']],
  ];
  for (const [name, events, expected] of cases) {
    const r = await run(events, w);
    assert.deepEqual(links(r), expected, name);
    assert.equal(r.state, 'failed', name);
    assert.equal(r.code, name === 'wrong vct' ? 'VCT_UNSUPPORTED' : 'CHAIN_BROKEN', name); // the first failing check of the first failing event
    const broken = r.events.find((e) => !e.ok)!;
    assert.equal(broken.event, undefined, `${name}: a broken link is not shown`);
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
    assert.equal(r.events[2]!.event, undefined);
    assert.deepEqual({ state: r.state, code: r.code }, { state: 'failed', code: `${step.code}` });
  }
});

test('a revoked or suspended event 2 is red at event 2 only; its successor still links', async () => {
  for (const [value, code] of [[1, 'REVOKED'], [2, 'SUSPENDED']] as const) {
    const w = await productWorld();
    w.setStatus('kiem-dinh', 11, value);
    await w.publish();
    const r = await verifyProductChain({ ...view, events: await w.chain(3) }, w.options());
    assert.deepEqual(failing(r), [[], [`status:${code}`], []]);
    assert.deepEqual({ state: r.state, ok: r.ok, code: r.code, complete: r.complete }, { state: 'failed', ok: false, code, complete: false });
    assert.equal(r.events[1]!.event?.congDoan, 'kiem_dinh'); // still shown, in red, with who signed it
    assert.equal(r.events[1]!.event?.issuer.ten, 'kiem-dinh (DEMO)');
  }
});

test('an issuer absent from the trust list: ISSUER_NOT_TRUSTED, status SKIPPED, its status list never fetched, its text not shown', async () => {
  const w = await productWorld({ issuers: [trustIssuer('nha-san-xuat'), trustIssuer('kiem-dinh')] });
  const r = await verifyProductChain({ ...view, events: await w.chain(3) }, w.options());
  assert.deepEqual(failing(r), [[], [], ['issuer_trust:ISSUER_NOT_TRUSTED', 'status:SKIPPED']]);
  assert.equal(r.events[2]!.event, undefined);
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
  assert.deepEqual(r, { state: 'failed', ok: false, code: 'TOO_LARGE', complete: false, missingStages: [], events: [] });
  assert.equal(hashes, 0);
  assert.deepEqual(w.urls(), []);
  // The total bound refuses the list itself, before any event is looked at.
  assert.deepEqual(await verifyProductChain({ ...view, events: Array(20).fill('x'.repeat(16_385)) }, options), { state: 'failed', ok: false, code: 'TOO_LARGE', complete: false, missingStages: [], events: [] });
  assert.equal(hashes, 0);
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
  assert.equal(bad.code, 'MALFORMED');
  const nonString = await w.craft('nha-san-xuat', { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: { html: img }, mo_ta: 'm' });
  assert.deepEqual(failing(await run([nonString], w)), [['product_chain:MALFORMED']]);
});

test('status lists unreachable: STATUS_UNAVAILABLE on every event; trust list unreachable: TRUST_LIST_UNAVAILABLE', async () => {
  const w = await productWorld();
  const events = await w.chain(3);
  for (const org of ORGS) w.served.routes[statusUriOf(org)] = new Error('down');
  const unavailable = await run(events, w);
  assert.deepEqual(failing(unavailable), Array(3).fill(['status:STATUS_UNAVAILABLE']));
  assert.deepEqual({ state: unavailable.state, code: unavailable.code }, { state: 'failed', code: 'STATUS_UNAVAILABLE' });
  assert.ok(unavailable.events.every((e) => e.event !== undefined), 'shown, with status not established');
  w.served.routes[TRUST_URL] = new Error('down');
  const r = await run(events, w);
  assert.deepEqual(failing(r), Array(3).fill(['issuer_trust:TRUST_LIST_UNAVAILABLE', 'status:SKIPPED']));
  assert.equal(r.code, 'TRUST_LIST_UNAVAILABLE');
  assert.ok(r.events.every((e) => e.event === undefined));
});

test('thoi_diem is bounded by the iat of its own event + 60 s, so a future-dated step cannot block later ones', async () => {
  const w = await productWorld();
  const iat = Math.floor(w.now.getTime() / 1000) - 600; // what craft() signs
  const at = (seconds: number) => new Date(seconds * 1000).toISOString();
  const first = (thoi_diem: string) => w.craft('nha-san-xuat', { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem, dia_diem: 'd', mo_ta: 'm' });
  assert.deepEqual(links(await run([await first(at(iat + 60))], w)), [null]);
  assert.deepEqual(links(await run([await first(at(iat + 61))], w)), ['CHAIN_BROKEN']);
  assert.deepEqual(links(await run([await first('0000-01-01T00:00:00Z')], w)), [null]); // no lower bound
  // A 9999 stage is broken itself, and the honest next stage still links: its time is not compared with 9999.
  const future = await first('9999-12-31T23:59:59.999Z');
  const r = await run([future, await w.issue(1, future)], w);
  assert.deepEqual(links(r), ['CHAIN_BROKEN', null]);
  // The issuer refuses both: a future instant and a non-ISO one.
  await assert.rejects(w.issue(0, undefined, { thoi_diem: '9999-12-31T23:59:59Z' }), /not be later than the time of issuance/);
  await assert.rejects(w.issue(0, undefined, { thoi_diem: '2026-01-02' }), /ISO 8601 UTC instant/);
  await assert.rejects(w.issue(0, undefined, { thoi_diem: '2026-01-02T08:00:00+07:00' }), /ISO 8601 UTC instant/);
  assert.equal(typeof (await w.issue(0, undefined, { thoi_diem: '0000-01-01T00:00:00Z' })), 'string');
});

test('events at index 3 and later are CHAIN_BROKEN without parsing, crypto or requests', async () => {
  const w = await productWorld();
  const full = await w.chain(3);
  let hashes = 0;
  const options = { ...w.options(), hasher: { sha256: (d: Uint8Array) => (hashes++, webCryptoHasher.sha256(d)) } };
  const r = await verifyProductChain({ ...view, events: [...full, full[2]!, 'garbage'] }, options);
  for (const i of [3, 4]) assert.deepEqual(r.events[i]!.checks.map((c) => [c.id, c.code]), [['product_chain', 'CHAIN_BROKEN']]);
  assert.deepEqual({ state: r.state, code: r.code }, { state: 'failed', code: 'CHAIN_BROKEN' });
  assert.equal(hashes, 3, 'only the three stages are hashed');
  assert.equal(w.urls().length, 4, 'trust list and three status lists only');
});

test('productEventHash: a fixed vector over the exact ASCII bytes, trailing "~" included', async () => {
  // node -e "console.log(require('node:crypto').createHash('sha256').update('eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUifQ.c2lnbmF0dXJl~','ascii').digest('base64url'))"
  const compact = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUifQ.c2lnbmF0dXJl~';
  assert.equal(await productEventHash(compact, webCryptoHasher), 'RCMAHQMeFv9yrZvq8TPYTeBwXaEx_bLmT7fXZMxCCxE');
  // The same without "~" (same command without it) differs: the separator is part of what is hashed.
  assert.equal(await productEventHash(compact.slice(0, -1), webCryptoHasher), 'TFV8xGOHcleNF8JqBg7VniZmNJ3SuIM8ZIa7mDFraVI');
});

test('a trusted diploma among product events: VCT_UNSUPPORTED and no request for the school status list', async () => {
  const school = 'truong-mau';
  const leaf = demoCerts(`orgs/${school}/vc.cert.pem`)[0]!;
  const entry = { ...trustIssuer('nha-san-xuat'), ma_to_chuc: parseCertificate(leaf).subject.organizationIdentifier!, ten: 'Trường', vct: [VCT.diploma], chung_thu: [{ sha256: fingerprintOf(leaf), muc_dich: 'vc' as const }] };
  delete entry.cong_doan;
  const w = await productWorld({ issuers: [...ORGS.map((o) => trustIssuer(o)), entry] });
  const signer = await demoSigner(school, 'vc');
  const iss = issOf(school);
  const diploma = `${await rawJws({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c }, { iss, vct: VCT.diploma, iat: Math.floor(w.now.getTime() / 1000) - 600, status: { status_list: { idx: 1, uri: `${iss}/status/1` } } }, signer)}~`;
  const r = await run([diploma], w);
  assert.deepEqual(failing(r), [['credential_type:VCT_UNSUPPORTED', 'status:SKIPPED', 'product_chain:CHAIN_BROKEN']]);
  assert.deepEqual(w.urls(), [TRUST_URL]);
});
