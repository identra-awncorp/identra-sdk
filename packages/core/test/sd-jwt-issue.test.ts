// Issuance (ADR-0001, ADR-0008, ADR-0012, ADR-0015 section 4) and decodeCredentialUnverified.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  base64UrlDecode,
  decodeCredentialUnverified,
  issueCredential,
  issueDiploma,
  issueProductEvent,
  utf8Decode,
  VCT,
  type ProductEventClaims,
  type RandomSource,
} from '@identra/sdk-core';
import { webCryptoRandom } from '@identra/sdk-core/webcrypto';
import { DIPLOMA, holderKey, ISS, issuerContext, issuerSigner, NOW_S, STATUS } from './helpers/sdjwt.js';
import { x5c } from './helpers/pki.js';

const PRODUCT: ProductEventClaims = {
  ma_san_pham: '(01)09520123456788(21)SN-0001',
  cong_doan: 'san_xuat',
  thoi_diem: '2026-05-30T01:00:00Z',
  dia_diem: 'Hà Nội',
  mo_ta: 'Sản xuất lô 1',
};

async function diploma(random: RandomSource = webCryptoRandom) {
  const holder = await holderKey();
  const compact = await issueDiploma({ ...(await issuerContext()), random, iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
  return { compact, holder };
}

describe('issueDiploma', () => {
  test('exact header, metadata, seven disclosures and exactly 10 _sd digests', async () => {
    const { compact, holder } = await diploma();
    const d = decodeCredentialUnverified(compact);
    assert.deepEqual(d.header, { alg: 'ES256', typ: 'dc+sd-jwt', x5c: x5c('vc') });
    assert.equal(d.payload['iss'], ISS);
    assert.equal(d.payload['vct'], VCT.diploma);
    assert.equal(d.payload['iat'], Math.floor(NOW_S));
    assert.equal(d.payload['exp'], undefined);
    assert.deepEqual(d.payload['cnf'], { jwk: holder.publicJwk });
    assert.deepEqual(d.payload['status'], { status_list: STATUS });
    assert.equal(d.payload['_sd_alg'], 'sha-256');
    assert.equal((d.payload['_sd'] as string[]).length, 10);
    for (const name of Object.keys(DIPLOMA)) assert.equal(d.payload[name], undefined, `${name} must not be visible`);
    assert.deepEqual(Object.fromEntries(d.disclosures.map((x) => [x.name, x.value])), DIPLOMA);
    assert.ok(compact.endsWith('~'));
  });

  test('salts come from the injected RandomSource, 16 bytes each', async () => {
    const calls: number[] = [];
    const recording: RandomSource = { bytes: (n) => (calls.push(n), webCryptoRandom.bytes(n)) };
    const { compact } = await diploma(recording);
    assert.deepEqual(calls, Array(10).fill(16), '7 disclosure salts and 3 decoy seeds');
    for (const encoded of compact.split('~').slice(1, -1)) {
      const [salt] = JSON.parse(utf8Decode(base64UrlDecode(encoded))) as [string];
      assert.equal(base64UrlDecode(salt).length, 16);
    }
  });

  test('two issuances of the same data share no digest', async () => {
    const a = decodeCredentialUnverified((await diploma()).compact).payload['_sd'] as string[];
    const b = decodeCredentialUnverified((await diploma()).compact).payload['_sd'] as string[];
    assert.equal(new Set([...a, ...b]).size, 20);
  });

  test('refuses an incomplete or mistyped claim set and a missing cnf', async () => {
    const ctx = await issuerContext();
    const { publicJwk } = await holderKey();
    const base = { ...ctx, iss: ISS, cnfJwk: publicJwk, status: STATUS, claims: DIPLOMA };
    const { ho_ten: _omit, ...missing } = DIPLOMA;
    void _omit;
    for (const claims of [missing, { ...DIPLOMA, extra: 'x' }, { ...DIPLOMA, nam_tot_nghiep: 2024 }, { ...DIPLOMA, ho_ten: '' }]) {
      await assert.rejects(issueDiploma({ ...base, claims: claims as never }), TypeError);
    }
    await assert.rejects(issueDiploma({ ...base, cnfJwk: undefined as never }), TypeError);
    await assert.rejects(issueDiploma({ ...base, cnfJwk: { ...publicJwk, crv: 'P-384' as 'P-256' } }), TypeError);
  });
});

describe('issueProductEvent', () => {
  test('every claim visible, no disclosures, no _sd, no cnf, no exp', async () => {
    const compact = await issueProductEvent({ ...(await issuerContext()), iss: ISS, status: STATUS, claims: { ...PRODUCT, prev: 'A'.repeat(43) } });
    const d = decodeCredentialUnverified(compact);
    assert.equal(d.isProductEvent, true);
    assert.deepEqual(d.disclosures, []);
    for (const k of ['_sd', '_sd_alg', 'cnf', 'exp']) assert.equal(d.payload[k], undefined, k);
    assert.equal(d.payload['cong_doan'], 'san_xuat');
    assert.equal(d.payload['prev'], 'A'.repeat(43));
    assert.equal(compact.split('~').length, 2);
  });

  test('refuses bad claims and a cnf', async () => {
    const ctx = await issuerContext();
    const base = { ...ctx, iss: ISS, status: STATUS, claims: PRODUCT };
    const bad: Partial<Record<keyof ProductEventClaims | 'extra', unknown>>[] = [
      { cong_doan: 'ban_le' },
      { mo_ta: 'x'.repeat(501) },
      { dia_diem: 42 },
      { ma_san_pham: '09520123456788' },
      { prev: 'not-a-digest' },
      { extra: 'x' },
    ];
    for (const patch of bad) await assert.rejects(issueProductEvent({ ...base, claims: { ...PRODUCT, ...patch } as never }), TypeError, JSON.stringify(patch));
    const { mo_ta: _omit, ...missing } = PRODUCT;
    void _omit;
    await assert.rejects(issueProductEvent({ ...base, claims: missing as never }), TypeError);
    const { publicJwk } = await holderKey();
    await assert.rejects(issueProductEvent({ ...base, cnfJwk: publicJwk } as never), TypeError);
    assert.ok(await issueProductEvent({ ...base, claims: { ...PRODUCT, mo_ta: 'x'.repeat(500) } }));
  });
});

describe('issueCredential refuses programmer errors', () => {
  const input = async () => ({
    ...(await issuerContext()),
    iss: ISS,
    vct: VCT.diploma,
    status: STATUS,
    claims: { ho_ten: 'A', nganh: 'B' },
    disclosable: ['ho_ten'],
  });
  test('a metadata claim made disclosable, iat included', async () => {
    for (const name of ['iat', 'iss', 'vct', 'nbf', 'exp', 'cnf', 'status']) {
      await assert.rejects(issueCredential({ ...(await input()), disclosable: [name] }), TypeError, name);
      await assert.rejects(issueCredential({ ...(await input()), claims: { [name]: 1 }, disclosable: [name] }), /can never be disclosable/, name);
      await assert.rejects(issueCredential({ ...(await input()), claims: { [name]: 1 }, disclosable: [] }), /not a subject claim name/, name);
    }
  });
  test('a signer without x5c, or whose leaf does not hold iss', async () => {
    const signer = await issuerSigner();
    const { x5c: _drop, ...noChain } = signer;
    void _drop;
    await assert.rejects(issueCredential({ ...(await input()), signer: noChain }), TypeError);
    await assert.rejects(issueCredential({ ...(await input()), signer: { ...signer, x5c: [signer.x5c![0]!] } }), TypeError);
    await assert.rejects(issueCredential({ ...(await input()), signer: await issuerSigner('status') }), TypeError, 'status leaf has no SAN');
    await assert.rejects(issueCredential({ ...(await input()), iss: 'https://api-identra.awncorp.vn/issuers/other', status: { idx: 1, uri: 'https://api-identra.awncorp.vn/issuers/other/status/1' } }), TypeError);
  });
  test('status, decoys, reserved names and times', async () => {
    const bad = [
      { status: { idx: -1, uri: STATUS.uri } },
      { status: { idx: 1.5, uri: STATUS.uri } },
      { status: { idx: 1, uri: 'https://elsewhere.example/status/1' } },
      { sdDigests: 0 },
      { disclosable: [], sdDigests: 3 },
      { disclosable: ['missing'] },
      { disclosable: ['ho_ten', 'ho_ten'] },
      { claims: { _sd: [] } },
      { claims: { '...': 1 } },
      { exp: 1.5 },
      { nbf: -1 },
      { iss: 'http://api-identra.awncorp.vn/issuers/truong-mau' },
    ];
    for (const patch of bad) await assert.rejects(issueCredential({ ...(await input()), ...patch } as never), TypeError, JSON.stringify(patch));
  });
});

test('decodeCredentialUnverified throws on a malformed compact', () => {
  assert.throws(() => decodeCredentialUnverified('not a credential'), TypeError);
});
