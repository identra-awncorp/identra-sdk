// appendProductEvent and checkProductEventForStorage on a fresh DEMO PKI with the real server
// services: file key store, trust list service (cong_doan scopes from make-trust-list-source.mjs),
// status list service, and the core registry and checker reading them through an in-memory fetch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createSignedTrustListRegistry, createStatusListChecker, decodeCredentialUnverified, issueProductEvent, productEventHash, type CongDoan, type HttpFetch,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import {
  appendProductEvent, checkProductEventForStorage, createFileKeyStore, createMemoryStatusListStorage, createStatusListService, createTrustListService,
  ProductChainRefusedError,
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

type Over = { org?: string; congDoan?: CongDoan; thoiDiem?: string; serial?: string };
async function append(existing: string[], over: Over = {}) {
  const stage = existing.length;
  const org = over.org ?? STAGES[Math.min(stage, 2)]![0];
  const { uri, idx } = await statusService.allocate(org);
  return appendProductEvent({
    gtin: GTIN, serial: over.serial ?? SERIAL, existing, verify: verifyOptions(),
    signer: await keyStore.signer(org, 'vc'), hasher: webCryptoHasher, random: webCryptoRandom, clock,
    iss: issuerUri(org), status: { uri, idx },
    claims: { congDoan: over.congDoan ?? STAGES[Math.min(stage, 2)]![1], thoiDiem: over.thoiDiem ?? TIMES[Math.min(stage, 2)]!, diaDiem: 'Hà Nội', moTa: 'Lô 7' },
  });
}
const store = (existing: string[], candidate: string) => checkProductEventForStorage({ gtin: GTIN, serial: SERIAL, existing, candidate }, verifyOptions());
const refused = (index: number | null, code: string) => (e: unknown) => e instanceof ProductChainRefusedError && e.index === index && e.code === code;
const statusOf = (compact: string) => (decodeCredentialUnverified(compact).payload['status'] as { status_list: { idx: number; uri: string } }).status_list;
const revoke = async (org: string, compact: string, status: 'revoked' | 'suspended' = 'revoked') => {
  const s = statusOf(compact);
  await statusService.setStatus(org, Number(s.uri.split('/').pop()), s.idx, status);
};

test('appendProductEvent builds a linked chain; each step passes the store check', async () => {
  const e0 = await append([]);
  assert.deepEqual(await store([], e0), { ok: true });
  const e1 = await append([e0]);
  assert.deepEqual(await store([e0], e1), { ok: true });
  const e2 = await append([e0, e1]);
  assert.deepEqual(await store([e0, e1], e2), { ok: true });
  assert.equal('prev' in decodeCredentialUnverified(e0).payload, false);
  assert.equal(decodeCredentialUnverified(e0).payload['ma_san_pham'], CODE);
  assert.equal(decodeCredentialUnverified(e1).payload['prev'], await productEventHash(e0, webCryptoHasher));
  assert.equal(decodeCredentialUnverified(e2).payload['prev'], await productEventHash(e1, webCryptoHasher));
  await assert.rejects(append([e0, e1, e2]), refused(3, 'CHAIN_BROKEN'), 'a complete chain is not extended');
});

test('appendProductEvent refuses a wrong stage or time (TypeError) and an existing chain that is not fully ok', async () => {
  const e0 = await append([]);
  const e1 = await append([e0]);
  await assert.rejects(append([], { congDoan: 'kiem_dinh', org: 'kiem-dinh' }), /congDoan must be san_xuat/);
  await assert.rejects(append([e0], { congDoan: 'phan_phoi', org: 'phan-phoi' }), /congDoan must be kiem_dinh/);
  await assert.rejects(append([e0], { thoiDiem: '2026-10-31T23:59:59Z' }), /earlier than the previous/);
  await assert.rejects(append([e0], { thoiDiem: '2026-11-02' }), /ISO 8601/);
  await assert.rejects(append([e0], { thoiDiem: '9999-01-01T00:00:00Z' }), /not be later than the time of issuance/);
  // A corrupted store: a forged or garbage predecessor, another product, a tampered byte.
  const tampered = e1.slice(0, -10) + (e1.at(-10) === 'A' ? 'B' : 'A') + e1.slice(-9);
  await assert.rejects(append([e0, tampered]), refused(1, 'SIGNATURE_INVALID'));
  await assert.rejects(append(['garbage~']), refused(0, 'MALFORMED'));
  await assert.rejects(append([e0], { serial: 'OTHER' }), refused(0, 'CHAIN_BROKEN'));
  await assert.rejects(append(Array(21).fill(e0)), refused(null, 'TOO_LARGE'));
  // A stored event signed by a trusted organisation that breaks a chain rule is refused before anything is signed.
  const signer = await keyStore.signer('nha-san-xuat', 'vc');
  const { uri, idx } = await statusService.allocate('nha-san-xuat');
  const odd = await issueProductEvent({ signer, hasher: webCryptoHasher, random: webCryptoRandom, clock, iss: issuerUri('nha-san-xuat'), status: { uri, idx }, claims: { ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0]!, dia_diem: 'd', mo_ta: 'm', prev: await productEventHash(e0, webCryptoHasher) } });
  await assert.rejects(append([odd]), refused(0, 'CHAIN_BROKEN')); // prev on the first event
  // A revoked or suspended predecessor is not extended.
  const s0 = await append([]);
  await revoke('nha-san-xuat', s0, 'suspended');
  await assert.rejects(append([s0]), refused(0, 'SUSPENDED'));
});

test('checkProductEventForStorage requires the stored chain fully ok and the candidate to extend it', async () => {
  const e0 = await append([]);
  const e1 = await append([e0]);
  const code = async (existing: string[], candidate: string) => {
    const r = await store(existing, candidate);
    return r.ok ? 'ok' : `${r.index}:${r.code}`;
  };
  const other = await append([], { serial: 'OTHER' });
  assert.equal(await code([], other), '0:CHAIN_BROKEN'); // another product
  assert.equal(await code([e0], e0), '1:CHAIN_BROKEN'); // repeated stage
  assert.equal(await code([e0], await append([await append([])])), '1:CHAIN_BROKEN'); // linked to another first event
  assert.equal(await code([e0, e1], e1.slice(0, -10) + (e1.at(-10) === 'A' ? 'B' : 'A') + e1.slice(-9)), '2:SIGNATURE_INVALID');
  assert.equal(await code([e0], await append([e0], { org: 'nha-san-xuat' })), '1:ISSUER_NOT_TRUSTED'); // manufacturer signs inspection
  assert.equal(await code([], 'garbage'), '0:MALFORMED');
  assert.equal(await code(['garbage~'], e1), '0:MALFORMED'); // the stored part is checked too
  assert.equal(await code(Array(20).fill(e0), e1), 'null:TOO_LARGE');
  const e2 = await append([e0, e1]);
  assert.equal(await code([e0, e1, e2], e2), '3:CHAIN_BROKEN'); // nothing after phan_phoi
  // A revoked candidate is refused with its checks; a revoked stored event blocks the next one.
  await revoke('kiem-dinh', e1);
  const r = await store([e0], e1);
  assert.equal(!r.ok && r.checks.find((c) => c.id === 'status')?.code, 'REVOKED');
  assert.equal(await code([e0, e1], e2), '1:REVOKED');
});
