// steps 1-8 and gating (docs/architecture.md section 3, ADR-0007).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64UrlEncode, ErrorCodes, issueDiploma, issueProductEvent, TrustListUnavailableError, utf8Encode, VCT } from '@identra/sdk-core';
import { x5c } from './helpers/pki.js';
import {
  check, codes, craft, DIPLOMA, disclosure, fakeStatus, fakeTrust, holderKey, ISS, issuerContext, issuerSigner, NOW_S, STATUS,
  TRUST_ENTRY, VC_FINGERPRINT, verifyOptions, visiblePayload, verifyAny,
} from './helpers/sdjwt.js';

const verify = async (compact: unknown, overrides = {}) => verifyAny(compact, verifyOptions(overrides));
async function expectCode(compact: unknown, id: string, code: string, overrides = {}) {
  const r = await verify(compact, overrides);
  assert.equal(r.ok, false);
  assert.equal(check(r, id as never).code, code, `${id}: ${JSON.stringify(codes(r))}`);
  return r;
}
const withPayload = (patch: Record<string, unknown>) => craft({ payload: { ...visiblePayload(), ...patch } });

describe('positive paths', () => {
  test('a stored diploma passes every listed check and returns the credential', async () => {
    const holder = await holderKey();
    const compact = await issueDiploma({ ...(await issuerContext()), iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
    const r = await verify(compact);
    assert.deepEqual(codes(r), [
      ['structure', null], ['algorithm', null], ['certificate_chain', null], ['signature', null], ['validity_time', null],
      ['credential_type', null], ['issuer_trust', null], ['status', null], ['holder_binding', null],
    ]);
    assert.equal(r.ok, true);
    assert.deepEqual(r.credential, {
      vct: VCT.diploma, iss: ISS, fingerprint: VC_FINGERPRINT, issuer: { maToChuc: TRUST_ENTRY.maToChuc, ten: TRUST_ENTRY.ten },
      iat: Math.floor(NOW_S), status: STATUS, cnfJwk: holder.publicJwk, claims: DIPLOMA,
    });
    assert.equal(r.chainChecks?.length, 6);
  });

  test('a product event passes without cnf or holder_binding', async () => {
    const compact = await issueProductEvent({
      ...(await issuerContext()), iss: ISS, status: STATUS,
      claims: { ma_san_pham: '(01)09520123456788(21)A1', cong_doan: 'san_xuat', thoi_diem: '2026-05-30T00:00:00Z', dia_diem: 'HN', mo_ta: 'lô 1' },
    });
    const r = await verify(compact);
    assert.equal(r.ok, true, JSON.stringify(codes(r)));
    assert.equal(r.checks.some((c) => c.id === 'holder_binding'), false);
    assert.equal(r.credential?.cnfJwk, undefined);
    assert.equal(r.credential?.claims?.['cong_doan'], 'san_xuat');
  });
});

describe('step 1 structure', () => {
  test('MALFORMED shapes', async () => {
    const good = await craft({});
    const jws = good.slice(0, -1);
    const [h, p] = jws.split('.') as [string, string];
    const b64 = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));
    const malformed: [string, unknown][] = [
      ['not a string', 42],
      ['no ~', jws],
      ['two-part JWS', `${h}.${p}~`],
      ['empty disclosure', `${jws}~~`],
      ['disclosure not base64url JSON', `${jws}~!!~`.replace('!!', 'AAA')],
      ['disclosure not an array', `${jws}~${b64({ a: 1 })}~`],
      ['non-ASCII character', `${jws}~é~`],
      ['payload not an object', await craft({ payload: [1, 2] as never })],
      ['iss missing', await craft({ payload: { ...visiblePayload(), iss: undefined } })],
      ['iat not a number', await withPayload({ iat: '1700000000' })],
      ['vct not a string', await withPayload({ vct: ['x'] })],
      ['exp not a number', await withPayload({ exp: 'never' })],
      ['status not an object', await withPayload({ status: 'ok' })],
    ];
    for (const [name, compact] of malformed) await expectCode(compact, 'structure', ErrorCodes.MALFORMED).catch((e) => assert.fail(`${name}: ${e.message}`));
  });
  test('the SD shape of the payload is checked in step 1, with or without disclosures', async () => {
    const digest = 'A'.repeat(43);
    const shapes: [string, Record<string, unknown>][] = [
      ['the same digest twice', { _sd: [digest, digest], _sd_alg: 'sha-256' }],
      ['_sd not an array', { _sd: digest, _sd_alg: 'sha-256' }],
      ['_sd with a non-digest', { _sd: [digest, 'short'], _sd_alg: 'sha-256' }],
      ['_sd with a non-string', { _sd: [7], _sd_alg: 'sha-256' }],
      ['_sd without _sd_alg', { _sd: [digest] }],
      ['_sd_alg other than sha-256', { _sd: [digest], _sd_alg: 'sha-512' }],
      ['_sd_alg other than sha-256, no _sd', { _sd_alg: 'SHA-256' }],
      ['nested _sd', { dia_chi: { _sd: [digest] } }],
      ['nested _sd_alg', { dia_chi: { _sd_alg: 'sha-256' } }],
      ['array-element digest', { quoc_tich: [{ '...': digest }] }],
      ['deeply nested', { a: [[{ b: [{ c: { _sd: [] } }] }]] }],
    ];
    for (const [name, patch] of shapes) {
      const compact = await withPayload(patch);
      const r = await expectCode(compact, 'structure', ErrorCodes.MALFORMED).catch((e) => assert.fail(`${name}: ${e.message}`));
      assert.equal(r.credential, undefined, name);
    }
    assert.equal(check(await verify(await withPayload({ _sd: [digest], _sd_alg: 'sha-256' })), 'structure').code, null, 'a valid shape with only decoys');
    assert.equal(check(await verify(await withPayload({ _sd_alg: 'sha-256' })), 'structure').code, null, '_sd_alg alone is allowed');
  });
  test('F1-1: a payload nested deeper than 32 levels is MALFORMED in step 1', async () => {
    const nested = (levels: number) => JSON.parse('['.repeat(levels) + ']'.repeat(levels)) as unknown;
    // The payload object is level 1.
    assert.equal(check(await verify(await withPayload({ a: nested(31) })), 'structure').code, null);
    for (const levels of [32, 4000]) await expectCode(await withPayload({ a: nested(levels) }), 'structure', ErrorCodes.MALFORMED);
  });
  test('a stored credential carrying a KB-JWT is MALFORMED', async () => {
    const compact = await craft({});
    await expectCode(`${compact}${compact.slice(0, -1)}`, 'structure', ErrorCodes.MALFORMED);
  });
  test('TYP_INVALID', async () => {
    for (const typ of ['JWT', 'statuslist+jwt', 'application/dc+sd-jwt', 'vc+sd-jwt', undefined]) {
      await expectCode(await craft({ header: { typ } }), 'structure', ErrorCodes.TYP_INVALID);
    }
  });
  test('TOO_LARGE: bytes and disclosures, checked before parsing', async () => {
    await expectCode('A'.repeat(16_385), 'structure', ErrorCodes.TOO_LARGE);
    await expectCode(await withPayload({ blob: 'x'.repeat(13_000) }), 'structure', ErrorCodes.TOO_LARGE);
    await expectCode(`x${'~'.repeat(52)}`, 'structure', ErrorCodes.TOO_LARGE);
    const many = Array.from({ length: 51 }, (_, i) => disclosure(`c${i}`, i));
    await expectCode(await craft({ disclosures: many }), 'structure', ErrorCodes.TOO_LARGE);
    const r = await verify(await craft({ disclosures: many.slice(0, 50) }));
    assert.equal(check(r, 'structure').code, null, '50 disclosures are allowed');
  });
});

describe('steps 2-4', () => {
  test('ALG_NOT_ALLOWED', async () => {
    for (const alg of ['none', 'HS256', 'EdDSA', 'ES384', 'RS256']) await expectCode(await craft({ header: { alg } }), 'algorithm', ErrorCodes.ALG_NOT_ALLOWED);
  });
  test('certificate chain codes through the credential path', async () => {
    const cases: [string[], string][] = [
      [[x5c('vc')[0]!], ErrorCodes.CERT_CHAIN_MALFORMED],
      [x5c('evil-vc', 'evil-issuing'), ErrorCodes.CERT_CHAIN_UNTRUSTED],
      [x5c('expired'), ErrorCodes.CERT_EXPIRED],
      [x5c('not-yet-valid'), ErrorCodes.CERT_NOT_YET_VALID],
      [x5c('ca-true'), ErrorCodes.CERT_CONSTRAINT_INVALID],
      [x5c('p384'), ErrorCodes.CERT_KEY_NOT_ALLOWED],
    ];
    for (const [chain, code] of cases) await expectCode(await craft({ header: { x5c: chain } }), 'certificate_chain', code);
    const r = await expectCode(await withPayload({ iss: 'https://api-identra.awncorp.vn/issuers/other' }), 'certificate_chain', ErrorCodes.ISSUER_MISMATCH);
    assert.equal(r.chainChecks?.at(-1)?.code, ErrorCodes.ISSUER_MISMATCH);
    await expectCode(await craft({ header: { x5c: undefined } }), 'certificate_chain', ErrorCodes.CERT_CHAIN_MALFORMED);
  });
  test('SIGNATURE_INVALID: payload changed after signing; signed by another key with the genuine chain', async () => {
    const [h, , s] = (await craft({})).split('~')[0]!.split('.');
    const changed = base64UrlEncode(utf8Encode(JSON.stringify({ ...visiblePayload(), status: { status_list: { idx: 43, uri: STATUS.uri } } })));
    await expectCode(`${h}.${changed}.${s}~`, 'signature', ErrorCodes.SIGNATURE_INVALID);
    const other = await issuerSigner('status');
    await expectCode(await craft({ signer: other, header: { x5c: x5c('vc') } }), 'signature', ErrorCodes.SIGNATURE_INVALID);
  });
});

describe('gating', () => {
  test('a failure in steps 1-4 lists every later check as SKIPPED and returns no credential', async () => {
    const r = await verify(await craft({ header: { alg: 'HS256' } }), { presentation: { nonce: 'n', audience: 'a' } });
    assert.deepEqual(codes(r), [
      ['structure', null], ['algorithm', 'ALG_NOT_ALLOWED'], ['certificate_chain', 'SKIPPED'], ['signature', 'SKIPPED'],
      ['validity_time', 'SKIPPED'], ['credential_type', 'SKIPPED'], ['issuer_trust', 'SKIPPED'], ['status', 'SKIPPED'], ['holder_binding', 'SKIPPED'],
    ]);
    assert.ok(r.checks.filter((c) => c.code === 'SKIPPED').every((c) => c.skipped === true && c.ok === false));
    assert.equal(r.credential, undefined);
  });
  test('steps 5-9 all run and all report when several fail at once', async () => {
    const trust = fakeTrust(null);
    const status = fakeStatus();
    const compact = await craft({ payload: { ...visiblePayload(), exp: NOW_S - 3600 }, disclosures: [disclosure('iat', 1)] });
    const r = await verify(compact, { supportedVcts: [VCT.productEvent], trustRegistry: trust, statusChecker: status });
    assert.deepEqual(codes(r).slice(4), [
      ['validity_time', 'EXPIRED'], ['credential_type', 'VCT_UNSUPPORTED'], ['issuer_trust', 'ISSUER_NOT_TRUSTED'], ['status', 'SKIPPED'], ['holder_binding', 'DISCLOSURE_INVALID'],
    ]);
    assert.equal(status.calls, 0, 'no status request for an untrusted issuer');
    assert.equal(r.credential?.issuer, null);
    assert.equal(r.credential?.claims, undefined, 'no claims when holder_binding failed');
  });
});

describe('step 5 validity_time, step 6 credential_type', () => {
  test('NOT_YET_VALID and EXPIRED with 60 s skew (59 s / 61 s)', async () => {
    const t = Math.floor(NOW_S);
    await expectCode(await withPayload({ iat: t + 61 }), 'validity_time', ErrorCodes.NOT_YET_VALID);
    await expectCode(await withPayload({ nbf: t + 61 }), 'validity_time', ErrorCodes.NOT_YET_VALID);
    await expectCode(await withPayload({ exp: t - 61 }), 'validity_time', ErrorCodes.EXPIRED);
    for (const patch of [{ iat: t + 59 }, { nbf: t + 59 }, { exp: t - 59 }]) {
      assert.equal(check(await verify(await withPayload(patch)), 'validity_time').code, null, JSON.stringify(patch));
    }
  });
  test('VCT_UNSUPPORTED; the issuer is trusted for that vct, yet no status request is made for it', async () => {
    const status = fakeStatus();
    const r = await expectCode(await craft({}), 'credential_type', ErrorCodes.VCT_UNSUPPORTED, { supportedVcts: [VCT.productEvent], statusChecker: status });
    assert.equal(check(r, 'issuer_trust').code, null);
    assert.equal(check(r, 'status').code, ErrorCodes.SKIPPED);
    assert.equal(status.calls, 0);
  });
});

describe('step 7 issuer_trust, step 8 status', () => {
  const productEvent = (cong_doan: string) =>
    withPayload({ vct: VCT.productEvent, ma_san_pham: '(01)09520123456788(21)A1', cong_doan, thoi_diem: 't', dia_diem: 'd', mo_ta: 'm' });
  test('ISSUER_NOT_TRUSTED for every rule; status is SKIPPED and the checker is not called', async () => {
    const entries = [null, { ...TRUST_ENTRY, mucDich: 'status' }, { ...TRUST_ENTRY, mucDich: 'request' }, { ...TRUST_ENTRY, maToChuc: 'VATVN-0100000009' }, { ...TRUST_ENTRY, vct: [VCT.productEvent] }, { ...TRUST_ENTRY, vct: undefined }, { ...TRUST_ENTRY, vct: `x${VCT.diploma}x` }, new Error('db down')];
    for (const entry of entries) {
      const status = fakeStatus();
      const r = await expectCode(await craft({}), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED, { trustRegistry: fakeTrust(entry as never), statusChecker: status });
      assert.equal(check(r, 'status').code, ErrorCodes.SKIPPED);
      assert.equal(status.calls, 0);
    }
    await expectCode(await craft({}), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED, { trustRegistry: fakeTrust(TRUST_ENTRY, 'other-fingerprint') });
    await expectCode(await productEvent('kiem_dinh'), 'issuer_trust', ErrorCodes.ISSUER_NOT_TRUSTED);
    assert.equal((await verify(await productEvent('san_xuat'))).ok, true);
  });
  test('TRUST_LIST_UNAVAILABLE', async () => {
    const status = fakeStatus();
    const r = await expectCode(await craft({}), 'issuer_trust', ErrorCodes.TRUST_LIST_UNAVAILABLE, { trustRegistry: fakeTrust(new TrustListUnavailableError()), statusChecker: status });
    assert.equal(check(r, 'status').code, ErrorCodes.SKIPPED);
    assert.equal(status.calls, 0);
  });
  test('REVOKED, SUSPENDED and STATUS_UNAVAILABLE from the checker', async () => {
    await expectCode(await craft({}), 'status', ErrorCodes.REVOKED, { statusChecker: fakeStatus('revoked') });
    await expectCode(await craft({}), 'status', ErrorCodes.SUSPENDED, { statusChecker: fakeStatus('suspended') });
    await expectCode(await craft({}), 'status', ErrorCodes.STATUS_UNAVAILABLE, { statusChecker: fakeStatus('unavailable') });
    await expectCode(await craft({}), 'status', ErrorCodes.STATUS_UNAVAILABLE, { statusChecker: fakeStatus(new Error('timeout')) });
    await expectCode(await craft({}), 'status', ErrorCodes.STATUS_UNAVAILABLE, { statusChecker: fakeStatus('maybe' as never) });
  });
  test('STATUS_UNAVAILABLE without calling the checker for a bad status reference', async () => {
    const refs: unknown[] = [
      undefined,
      {},
      { status_list: { idx: -1, uri: STATUS.uri } },
      { status_list: { idx: 1.5, uri: STATUS.uri } },
      { status_list: { idx: '1', uri: STATUS.uri } },
      { status_list: { uri: STATUS.uri } },
      { status_list: { idx: 1, uri: 'http://api-identra.awncorp.vn/issuers/truong-mau/status/1' } },
      { status_list: { idx: 1, uri: 'https://evil.example/issuers/truong-mau/status/1' } },
      { status_list: { idx: 1, uri: `${ISS}/statusx/1` } },
      { status_list: { idx: 1, uri: `${ISS}-other/status/1` } },
    ];
    for (const status of refs) {
      const checker = fakeStatus();
      await expectCode(await withPayload({ status }), 'status', ErrorCodes.STATUS_UNAVAILABLE, { statusChecker: checker });
      assert.equal(checker.calls, 0, JSON.stringify(status));
    }
  });
});

test('detail strings never carry claim values', async () => {
  const holder = await holderKey();
  const compact = await issueDiploma({ ...(await issuerContext()), iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
  const results = [
    await verify(compact, { supportedVcts: [], trustRegistry: fakeTrust(null) }),
    await verify(`${compact}${disclosure('ho_ten', DIPLOMA.ho_ten)}~`),
    await verify(compact, { presentation: { nonce: 'n', audience: 'a' } }),
  ];
  const details = JSON.stringify(results.flatMap((r) => r.checks.map((c) => c.detail ?? '')));
  for (const value of [...Object.values(DIPLOMA), compact.slice(0, 40)]) assert.equal(details.includes(value), false, value);
});

test('programmer errors throw', async () => {
  await assert.rejects(verifyAny('x', { ...verifyOptions(), now: new Date('x') }), TypeError);
  await assert.rejects(verifyAny('x', { ...verifyOptions(), statusChecker: undefined as never }), TypeError);
  await assert.rejects(verifyAny('x', verifyOptions({ presentation: { nonce: '', audience: 'a' } })), TypeError);
});
