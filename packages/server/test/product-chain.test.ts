// appendProductEvent and checkProductEventForStorage on a fresh DEMO PKI with the real server
// services: file key store, trust list service (cong_doan scopes from make-trust-list-source.mjs),
// status list service, and the core registry and checker reading them through an in-memory fetch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createSignedTrustListRegistry, createStatusListChecker, decodeCredentialUnverified, productEventHash, type CongDoan, type HttpFetch,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  appendProductEvent, checkProductEventForStorage, createFileKeyStore, createMemoryStatusListStorage, createStatusListService, createTrustListService,
} from '@identra/sdk-server';
import { fakeClock, freshDemoPki, issuerUri, trustListSource, validatorFor } from './helpers.js';

const DEMO = freshDemoPki();
const keyStore = createFileKeyStore(DEMO);
const clock = fakeClock();
const trustList = createTrustListService({ source: () => trustListSource(DEMO), keyStore, clock });
const statusService = createStatusListService({ issuerUri, keyStore, storage: createMemoryStatusListStorage(), random: webCryptoRandom, clock });
const GTIN = '09520123456788';
const SERIAL = 'LOT7-0042';
const CODE = `(01)${GTIN}(21)${SERIAL}`;
const STAGES: [string, CongDoan][] = [['nha-san-xuat', 'san_xuat'], ['kiem-dinh', 'kiem_dinh'], ['phan-phoi', 'phan_phoi']];
const TIMES = ['2026-11-01T08:00:00Z', '2026-11-02T08:00:00Z', '2026-11-03T08:00:00Z'];

const STATUS_PATH = /^https:\/\/api-identra\.awncorp\.vn\/issuers\/([a-z-]+)\/status\/([0-9]+)$/;
const fetch: HttpFetch = async (url) => {
  const m = STATUS_PATH.exec(url);
  const body = url === 'https://api-identra.awncorp.vn/trust-list' ? await trustList.token() : m ? await statusService.token(m[1]!, Number(m[2])) : null;
  return { status: body === null ? 404 : 200, headers: { get: () => null }, text: async () => body ?? '' };
};
function verifyOptions() {
  const chainValidator = validatorFor(DEMO);
  const trustRegistry = createSignedTrustListRegistry({ url: 'https://api-identra.awncorp.vn/trust-list', fetch, verifier: webCryptoVerifier, chainValidator, clock });
  const statusChecker = createStatusListChecker({ fetch, verifier: webCryptoVerifier, chainValidator, trustRegistry, clock, maxAgeSeconds: 0 });
  return { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, now: clock.now() };
}

async function append(stage: number, previous: string | undefined, over: { org?: string; congDoan?: CongDoan; maSanPham?: string; thoiDiem?: string } = {}) {
  const org = over.org ?? STAGES[stage]![0];
  return appendProductEvent({
    ...(previous !== undefined ? { previous } : {}),
    signer: await keyStore.signer(org, 'vc'), hasher: webCryptoHasher, random: webCryptoRandom, clock,
    iss: issuerUri(org), status: await statusService.allocate(org),
    claims: { maSanPham: over.maSanPham ?? CODE, congDoan: over.congDoan ?? STAGES[stage]![1], thoiDiem: over.thoiDiem ?? TIMES[stage]!, diaDiem: 'Hà Nội', moTa: 'Lô 7' },
  });
}

test('appendProductEvent builds a linked chain: no prev on the first, prev = hash of the previous compact', async () => {
  const e0 = await append(0, undefined);
  const e1 = await append(1, e0);
  const e2 = await append(2, e1);
  assert.equal('prev' in decodeCredentialUnverified(e0).payload, false);
  assert.equal(decodeCredentialUnverified(e1).payload['prev'], await productEventHash(e0, webCryptoHasher));
  assert.equal(decodeCredentialUnverified(e2).payload['prev'], await productEventHash(e1, webCryptoHasher));
  for (let i = 0; i < 3; i++) {
    const existing = [e0, e1, e2].slice(0, i);
    assert.deepEqual(await checkProductEventForStorage({ gtin: GTIN, serial: SERIAL, existing, candidate: [e0, e1, e2][i]! }, verifyOptions()), { ok: true });
  }
});

test('appendProductEvent refuses a stage out of order, another product, bad or backwards thoi_diem, a non-event previous', async () => {
  const e0 = await append(0, undefined);
  const e1 = await append(1, e0);
  const e2 = await append(2, e1);
  await assert.rejects(append(1, undefined), /congDoan must be san_xuat/);
  await assert.rejects(append(2, e0), /congDoan must be kiem_dinh/);
  await assert.rejects(append(1, e0, { congDoan: 'san_xuat', org: 'nha-san-xuat' }), /congDoan must be kiem_dinh/);
  await assert.rejects(append(2, e2), /last stage/);
  await assert.rejects(append(1, e0, { maSanPham: `(01)${GTIN}(21)OTHER` }), /maSanPham differs/);
  await assert.rejects(append(1, e0, { thoiDiem: '2026-10-31T23:59:59Z' }), /earlier than the previous/);
  await assert.rejects(append(1, e0, { thoiDiem: '2026-11-02' }), /ISO 8601/);
  await assert.rejects(append(1, 'not-a-credential~'), /not a credential/);
  await assert.rejects(append(0, undefined, { maSanPham: '(01)09520123456789(21)A' }), /GTIN-14 with a valid check digit/);
});

test('checkProductEventForStorage rejects each wrong next event with its code', async () => {
  const e0 = await append(0, undefined);
  const e1 = await append(1, e0);
  const other = await append(0, undefined, { maSanPham: `(01)${GTIN}(21)OTHER` });
  const check = (existing: string[], candidate: string) => checkProductEventForStorage({ gtin: GTIN, serial: SERIAL, existing, candidate }, verifyOptions());
  const code = async (existing: string[], candidate: string) => {
    const r = await check(existing, candidate);
    return r.ok ? 'ok' : r.code;
  };
  assert.equal(await code([], other), 'CHAIN_BROKEN'); // another product
  assert.equal(await code([e0], e0), 'CHAIN_BROKEN'); // repeated stage
  assert.equal(await code([e0], await append(1, await append(0, undefined))), 'CHAIN_BROKEN'); // linked to another first event
  assert.equal(await code([e0, e1], e1.slice(0, -10) + (e1.at(-10) === 'A' ? 'B' : 'A') + e1.slice(-9)), 'SIGNATURE_INVALID');
  assert.equal(await code([e0], await append(1, e0, { org: 'nha-san-xuat', congDoan: 'kiem_dinh' })), 'ISSUER_NOT_TRUSTED'); // manufacturer signs inspection
  assert.equal(await code([], 'garbage'), 'MALFORMED');
  assert.equal(await code(Array(20).fill(e0), e1), 'TOO_LARGE');
  // A revoked candidate is refused with its checks; revoking an earlier event does not block the next.
  const status = (decodeCredentialUnverified(e1).payload['status'] as { status_list: { idx: number; uri: string } }).status_list;
  await statusService.setStatus('kiem-dinh', Number(status.uri.split('/').pop()), status.idx, 'revoked');
  const revoked = await check([e0], e1);
  assert.equal(revoked.ok, false);
  assert.equal(!revoked.ok && revoked.checks.find((c) => c.id === 'status')?.code, 'REVOKED');
  assert.equal(await code([e0, e1], await append(2, e1)), 'ok');
});
