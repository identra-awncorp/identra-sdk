// Policy decisions of the GĐ2/GĐ3 review: exact status URI form (R1), uniform skip lists (R3),
// the two entry points (R4), claims only for a fully valid result (R5), issuance hardening (R6),
// KB-JWT exp/nbf (R8), exact boundaries and the privacy of every message (R10).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  createPresentation, ErrorCodes, issueCredential, issueDiploma, VCT, verifyPresentation, verifyStoredCredential, type Signer,
} from '@identra/sdk-core';
import { webCryptoHasher } from '@identra/sdk-core/webcrypto';
import { NOW, x5c } from './helpers/pki.js';
import {
  addKb, AUD, check, codes, craft, DIPLOMA, disclosure, fakeStatus, fakeTrust, holderKey, ISS, issuerContext, issuerSigner, NONCE, NOW_S,
  presentationOptions, STATUS, verifyOptions, visiblePayload,
} from './helpers/sdjwt.js';

const t = Math.floor(NOW_S);
async function diploma(holder?: Signer) {
  holder ??= await holderKey();
  const compact = await issueDiploma({ ...(await issuerContext()), iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
  return { compact, holder };
}
const present = (compact: string, holder: Signer, disclose = ['ho_ten', 'nganh']) =>
  createPresentation({ compact, disclose, holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: webCryptoHasher });
const withoutKb = (p: string) => p.slice(0, p.lastIndexOf('~') + 1);

// The reviewer's bypass strings for the status URI (attacks.mjs), all of which must fail.
const BYPASSES = [
  `${ISS}/status/../x`, `${ISS}/status/../../nha-san-xuat/status/1`, `${ISS}/status/%2e%2e/%2e%2e/x`, `${ISS}/status/\\..\\..\\x`,
  `${ISS}/status/1 `, `${ISS}/status/1#frag`, `${ISS}/status/1?x=https://evil`, `${ISS}/status/@evil.example`, `${ISS}/status/\t../x`,
  'HTTPS://api-identra.awncorp.vn/issuers/truong-mau/status/1', 'https://api-identra.awncorp.vn:443/issuers/truong-mau/status/1',
  'https://user@api-identra.awncorp.vn/issuers/truong-mau/status/1',
  `${ISS}/status/0`, `${ISS}/status/01`, `${ISS}/status/1000000000`, `${ISS}/status/`, `${ISS}/status/1/`, `${ISS}/status/-1`, `${ISS}/status/1.0`,
];

describe('R1: the status URI is exactly <iss>/status/<n>', () => {
  test('verification: each bypass is STATUS_UNAVAILABLE and the checker is never called', async () => {
    for (const uri of BYPASSES) {
      const checker = fakeStatus();
      const r = await verifyStoredCredential(await craft({ payload: { ...visiblePayload(), status: { status_list: { idx: 1, uri } } } }), verifyOptions({ statusChecker: checker }));
      assert.equal(check(r, 'status').code, ErrorCodes.STATUS_UNAVAILABLE, JSON.stringify(uri));
      assert.equal(checker.calls, 0, JSON.stringify(uri));
    }
    for (const uri of [`${ISS}/status/1`, `${ISS}/status/999999999`]) {
      const r = await verifyStoredCredential(await craft({ payload: { ...visiblePayload(), status: { status_list: { idx: 1, uri } } } }), verifyOptions());
      assert.equal(r.ok, true, uri);
    }
  });
  test('issuance refuses each bypass', async () => {
    const ctx = await issuerContext();
    const { publicJwk } = await holderKey();
    for (const uri of BYPASSES) {
      await assert.rejects(issueDiploma({ ...ctx, iss: ISS, cnfJwk: publicJwk, status: { idx: 1, uri }, claims: DIPLOMA }), TypeError, JSON.stringify(uri));
    }
  });
});

describe('R3: the same checks are listed whichever of steps 1-4 fails', () => {
  const later = ['validity_time', 'credential_type', 'issuer_trust', 'status'];
  const gated = ['structure', 'algorithm', 'certificate_chain', 'signature'];
  const failures = async (disclosures: string[]) => [
    await craft({ header: { typ: 'JWT' }, disclosures }),
    await craft({ header: { alg: 'HS256' }, disclosures }),
    await craft({ header: { x5c: [x5c('vc')[0]!] }, disclosures }),
    await craft({ signer: await issuerSigner('status'), header: { x5c: x5c('vc') }, disclosures }),
  ];
  const expected = (failedAt: number, holder: boolean) => [
    ...gated.map((id, i) => [id, i < failedAt ? null : i === failedAt ? 'x' : 'SKIPPED']),
    ...[...later, ...(holder ? ['holder_binding'] : [])].map((id) => [id, 'SKIPPED']),
  ];
  const shape = (r: Awaited<ReturnType<typeof verifyStoredCredential>>) => codes(r).map(([id, code], i) => [id, code !== null && code !== 'SKIPPED' && i < 4 ? 'x' : code]);
  test('stored, with disclosures: holder_binding is listed for every failure', async () => {
    for (const [i, compact] of (await failures([disclosure('ho_ten', 'A')])).entries()) assert.deepEqual(shape(await verifyStoredCredential(compact, verifyOptions())), expected(i, true), `step ${i + 1}`);
  });
  test('stored, without disclosures: holder_binding is never listed', async () => {
    for (const [i, compact] of (await failures([])).entries()) assert.deepEqual(shape(await verifyStoredCredential(compact, verifyOptions())), expected(i, false), `step ${i + 1}`);
  });
  test('presentation: holder_binding is always listed', async () => {
    const holder = await holderKey();
    for (const [i, compact] of (await failures([])).entries()) {
      assert.deepEqual(shape(await verifyPresentation(await addKb(compact, holder), presentationOptions())), expected(i, true), `step ${i + 1}`);
    }
  });
});

describe('R4: two entry points that cannot be confused', () => {
  test('wrong options are programmer errors', async () => {
    await assert.rejects(verifyStoredCredential('x', presentationOptions()), /use verifyPresentation/);
    await assert.rejects(verifyPresentation('x', verifyOptions() as never), /needs options.presentation/);
  });
  test('verifyPresentation requires the KB-JWT and cnf; verifyStoredCredential refuses a KB-JWT', async () => {
    const { compact, holder } = await diploma();
    assert.equal(check(await verifyPresentation(compact, presentationOptions()), 'holder_binding').code, ErrorCodes.KB_INVALID);
    const productLike = await craft({});
    const r = await verifyPresentation(await addKb(productLike, holder), presentationOptions());
    assert.equal(check(r, 'holder_binding').code, ErrorCodes.KB_INVALID, 'no cnf: nothing to prove possession of');
    assert.equal(check(await verifyStoredCredential(await present(compact, holder), verifyOptions()), 'structure').code, ErrorCodes.MALFORMED);
    assert.equal((await verifyPresentation(await present(compact, holder), presentationOptions())).ok, true);
  });
});

describe('R5: claims only when the whole result is ok', () => {
  test('untrusted, revoked, expired or unsupported: credential metadata yes, claims no', async () => {
    const { compact } = await diploma();
    for (const overrides of [{ trustRegistry: fakeTrust(null) }, { statusChecker: fakeStatus('revoked') }, { supportedVcts: [VCT.productEvent] }]) {
      const r = await verifyStoredCredential(compact, verifyOptions(overrides));
      assert.equal(r.ok, false);
      assert.equal(r.credential?.iss, ISS, 'steps 1-4 passed, so the metadata is returned');
      assert.equal(r.credential?.claims, undefined, JSON.stringify(Object.keys(overrides)));
    }
    const expired = await verifyStoredCredential(await craft({ payload: { ...visiblePayload(), exp: t - 3600, nganh: 'x' }, disclosures: [disclosure('ho_ten', 'A')] }), verifyOptions());
    assert.equal(check(expired, 'validity_time').code, ErrorCodes.EXPIRED);
    assert.equal(expired.credential?.claims, undefined);
    assert.deepEqual((await verifyStoredCredential(compact, verifyOptions())).credential?.claims, DIPLOMA);
  });
});

describe('R6: issuance refuses what JSON or a verifier would not carry', () => {
  const input = async (claims: Record<string, unknown>, disclosable: string[] = []) => ({ ...(await issuerContext()), iss: ISS, vct: VCT.diploma, status: STATUS, claims, disclosable });
  test('prototype and reserved claim names, at the top and nested', async () => {
    for (const json of ['{"__proto__":{"x":1}}', '{"a":{"__proto__":1}}', '{"a":[{"_sd":[]}]}', '{"a":{"...":"d"}}', '{"a":{"_sd_alg":"x"}}']) {
      await assert.rejects(issueCredential(await input(JSON.parse(json))), TypeError, json);
    }
    for (const name of ['constructor', 'prototype', '_sd', '_sd_alg', '...', 'iss', 'cnf']) await assert.rejects(issueCredential(await input({ [name]: 1 })), TypeError, name);
  });
  test('values JSON cannot carry unchanged', async () => {
    const cycle: Record<string, unknown> = {};
    cycle['self'] = cycle;
    for (const value of [undefined, () => 1, Symbol('s'), 10n, NaN, Infinity, -Infinity, new Date(0), new Map(), [1, undefined], { a: NaN }, cycle]) {
      await assert.rejects(issueCredential(await input({ a: value })), TypeError, String(typeof value));
    }
    assert.ok(await issueCredential(await input({ a: null, b: [1, 'x', true, { c: Object.create(null) }], d: -0.5 })));
  });
  test('the verifier limits are enforced before returning, and library errors become TypeError without values', async () => {
    await assert.rejects(issueCredential(await input({ blob: 'secret-value-'.repeat(1400) })), /would exceed 16384 bytes/);
    const many = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`c${i}`, i]));
    await assert.rejects(issueCredential(await input(many, Object.keys(many))), /more than 50/);
    const signer = await issuerSigner();
    const broken = { ...signer, sign: async () => new Uint8Array(70) };
    const err = await issueCredential({ ...(await input({ secret: 'do-not-echo-me' })), signer: broken }).catch((e: unknown) => e as Error);
    assert.ok(err instanceof TypeError);
    assert.equal(err.message.includes('do-not-echo-me'), false);
  });
});

describe('R8, R10: exact boundaries', () => {
  async function bound() {
    const { compact, holder } = await diploma();
    return { sdJwt: withoutKb(await present(compact, holder)), holder };
  }
  const kbCode = async (sdJwt: string, holder: Signer, payload: Record<string, unknown>) =>
    check(await verifyPresentation(await addKb(sdJwt, holder, { payload }), presentationOptions()), 'holder_binding').code;
  test('KB-JWT iat at exactly t-360 and t+60 is accepted, one second beyond is not', async () => {
    const { sdJwt, holder } = await bound();
    assert.equal(await kbCode(sdJwt, holder, { iat: t - 360 }), null);
    assert.equal(await kbCode(sdJwt, holder, { iat: t + 60 }), null);
    assert.equal(await kbCode(sdJwt, holder, { iat: t - 361 }), ErrorCodes.KB_INVALID);
    assert.equal(await kbCode(sdJwt, holder, { iat: t + 61 }), ErrorCodes.KB_INVALID);
  });
  test('KB-JWT exp and nbf, when present, with 60 s skew', async () => {
    const { sdJwt, holder } = await bound();
    for (const [payload, code] of [
      [{ exp: t - 59 }, null], [{ exp: t - 60 }, ErrorCodes.KB_INVALID], [{ exp: 'soon' }, ErrorCodes.KB_INVALID],
      [{ nbf: t + 60 }, null], [{ nbf: t + 61 }, ErrorCodes.KB_INVALID], [{ nbf: null }, ErrorCodes.KB_INVALID],
    ] as const) assert.equal(await kbCode(sdJwt, holder, payload), code, JSON.stringify(payload));
  });
  test('credential exp exactly at t-60 is expired; iat and nbf exactly at t+60 are valid', async () => {
    const at = async (patch: Record<string, unknown>) => check(await verifyStoredCredential(await craft({ payload: { ...visiblePayload(), ...patch } }), verifyOptions()), 'validity_time').code;
    assert.equal(await at({ exp: t - 60 }), ErrorCodes.EXPIRED);
    assert.equal(await at({ exp: t - 59 }), null);
    assert.equal(await at({ iat: t + 60 }), null);
    assert.equal(await at({ nbf: t + 60 }), null);
    assert.equal(await at({ nbf: t + 61 }), ErrorCodes.NOT_YET_VALID);
  });
  test('nbf of the wrong type, cnf of the wrong shape, and a cnf.jwk carrying d', async () => {
    const structure = async (patch: Record<string, unknown>) => check(await verifyStoredCredential(await craft({ payload: { ...visiblePayload(), ...patch } }), verifyOptions()), 'structure').code;
    assert.equal(await structure({ nbf: '1700000000' }), ErrorCodes.MALFORMED);
    assert.equal(await structure({ cnf: 'jwk' }), ErrorCodes.MALFORMED);
    assert.equal(await structure({ cnf: [1] }), ErrorCodes.MALFORMED);
    const holder = await holderKey();
    for (const cnf of [{ jwk: 'x' }, { jwk: { ...holder.publicJwk, d: 'AAAA' } }]) {
      const compact = await craft({ payload: { ...visiblePayload(), cnf } });
      assert.equal(check(await verifyPresentation(await addKb(compact, holder), presentationOptions()), 'holder_binding').code, ErrorCodes.KB_INVALID, JSON.stringify(cnf));
      assert.equal((await verifyStoredCredential(compact, verifyOptions())).credential?.cnfJwk, undefined);
    }
  });
});

test('R10: no detail or thrown message carries a claim value, a disclosure, the KB-JWT or the compact', async () => {
  const holder = await holderKey();
  const { compact } = await diploma(holder);
  const presentation = await present(compact, holder, Object.keys(DIPLOMA));
  const kb = presentation.slice(presentation.lastIndexOf('~') + 1);
  const secrets = [...Object.values(DIPLOMA), ...compact.split('~').slice(1, -1), kb, compact, presentation, withoutKb(presentation)];
  const messages: string[] = [];
  const collect = (r: Awaited<ReturnType<typeof verifyStoredCredential>>) => messages.push(...r.checks.map((c) => c.detail ?? ''), ...(r.chainChecks ?? []).map((c) => c.detail ?? ''));
  const variants = [
    compact, presentation, `${compact}${disclosure('ho_ten', DIPLOMA.ho_ten)}~`, `${compact}${compact.split('~')[1]}~`, presentation.slice(0, -2),
    withoutKb(presentation) + (await addKb(withoutKb(presentation), await holderKey())).slice(withoutKb(presentation).length), compact.replace('.', ''), `${compact} `,
  ];
  for (const v of variants) {
    for (const overrides of [{}, { trustRegistry: fakeTrust(null) }, { statusChecker: fakeStatus('revoked') }, { supportedVcts: [] }, { now: new Date('2040-01-01T00:00:00Z') }]) {
      collect(await verifyStoredCredential(v, verifyOptions(overrides)));
      collect(await verifyPresentation(v, presentationOptions(overrides)));
      collect(await verifyPresentation(v, presentationOptions({ ...overrides, presentation: { nonce: 'other', audience: 'other' } })));
    }
  }
  const thrown = async (p: Promise<unknown>) => p.then(() => assert.fail('expected a throw'), (e: Error) => messages.push(e.message));
  const ctx = await issuerContext();
  await thrown(issueDiploma({ ...ctx, iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: { ...DIPLOMA, nam_tot_nghiep: 2024 as never } }));
  await thrown(issueDiploma({ ...ctx, iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: { ...DIPLOMA, extra: DIPLOMA.ho_ten } as never }));
  await thrown(createPresentation({ compact: presentation, disclose: [], holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: webCryptoHasher }));
  await thrown(createPresentation({ compact, disclose: ['email'], holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher: webCryptoHasher }));
  assert.ok(messages.length > 200);
  const all = messages.join('\n');
  for (const secret of secrets) assert.equal(all.includes(secret), false, `leaked: ${secret.slice(0, 30)}`);
});
