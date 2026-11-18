// The benchmark world: the DEMO PKI (.pki/demo, made by `sh scripts/pki/ensure-test-pki.sh`), one
// diploma issuer (truong-mau), three product organisations, a trust list of five organisations, status
// lists, all served by an in-memory fetch. Time is fixed (one hour after the newest certificate), so
// every token and cache stays valid for the whole run and no timing includes a refetch.
import { existsSync, readFileSync } from 'node:fs';
import {
  base64Decode, base64UrlEncode, createCertificateChainValidator, createPresentation, createSignedTrustListRegistry, createStatusList, createStatusListChecker,
  createStatusListToken, createTrustListToken, issueDiploma, issueProductEvent, parseCertificate, productEventHash, VCT,
} from '@identra/sdk-core';
import { createWebCryptoSigner, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createNobleSigner, generateSecretKey, nobleHasher, nobleVerifier } from '@identra/sdk-app';

const DEMO = new URL('../.pki/demo/', import.meta.url);
if (!existsSync(new URL('root.cert.pem', DEMO))) throw new Error('.pki/demo is missing: run `sh scripts/pki/ensure-test-pki.sh` first');
const read = (path) => readFileSync(new URL(path, DEMO), 'utf8');
const pemCerts = (pem) => [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map((m) => m[1].replace(/\s+/g, ''));
const certB64 = (path) => pemCerts(read(path)); // base64 DER entries, chain order

export const ORIGIN = 'https://api-identra.awncorp.vn';
export const ISS = `${ORIGIN}/issuers/truong-mau`;
export const TRUST_URL = `${ORIGIN}/trust-list`;
export const AUDIENCE = 'x509_hash:bench-verifier';
export const GTIN = '09520123456788';
export const SERIAL = 'SN-0001';
export const DIPLOMA = {
  ho_ten: 'Nguyễn Văn A', ngay_sinh: '2001-02-03', ma_sinh_vien: 'SV123456', nganh: 'Khoa học máy tính',
  hang_tot_nghiep: 'Giỏi', nam_tot_nghiep: '2024', so_hieu_bang: 'B-0001',
};
const PRODUCT_ORGS = [['nha-san-xuat', 'san_xuat'], ['kiem-dinh', 'kiem_dinh'], ['phan-phoi', 'phan_phoi']];
const statusUri = (org) => `${ORIGIN}/issuers/${org}/status/1`;

// Deterministic PRNG, so the "1% set" status list is the same on every run.
function mulberry32(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export async function buildWorld() {
  const allCerts = ['orgs/truong-mau/vc.cert.pem', 'orgs/truong-mau/status.cert.pem', 'trust-list-signer/trust-list.cert.pem',
    ...PRODUCT_ORGS.flatMap(([o]) => [`orgs/${o}/vc-product.cert.pem`, `orgs/${o}/status.cert.pem`])];
  const NOW = new Date(Math.max(...allCerts.map((f) => parseCertificate(base64Decode(certB64(f)[0])).notBefore.getTime())) + 3600_000);
  const clock = { now: () => NOW };
  const trustedRoots = [base64Decode(certB64('root.cert.pem')[0])];
  const fingerprint = async (path) => base64UrlEncode(await webCryptoHasher.sha256(base64Decode(certB64(path)[0])));
  const orgId = (path) => parseCertificate(base64Decode(certB64(path)[0])).subject.organizationIdentifier;
  const signer = (org, purpose) => createWebCryptoSigner({ privateKey: read(`orgs/${org}/${purpose}.key.pem`), x5c: certB64(`orgs/${org}/${purpose}.chain.pem`) });

  const chainValidators = {
    webcrypto: createCertificateChainValidator({ trustedRoots, verifier: webCryptoVerifier, hasher: webCryptoHasher }),
    noble: createCertificateChainValidator({ trustedRoots, verifier: nobleVerifier, hasher: nobleHasher }),
  };
  const backends = {
    webcrypto: { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator: chainValidators.webcrypto },
    noble: { verifier: nobleVerifier, hasher: nobleHasher, chainValidator: chainValidators.noble },
  };

  // --- trust list content: 4 issuers + 1 verifier = 5 organisations -------------------------------
  const validity = { validFrom: new Date(NOW.getTime() - 86400_000).toISOString(), validUntil: new Date(NOW.getTime() + 3650 * 86400_000).toISOString() };
  const trustContent = {
    issuers: [
      {
        ma_to_chuc: orgId('orgs/truong-mau/status.cert.pem'), ten: 'Trường Mẫu (DEMO)',
        chung_thu: [{ sha256: await fingerprint('orgs/truong-mau/vc.cert.pem'), muc_dich: 'vc' }, { sha256: await fingerprint('orgs/truong-mau/status.cert.pem'), muc_dich: 'status' }],
        vct: [VCT.diploma], ...validity,
      },
      ...(await Promise.all(PRODUCT_ORGS.map(async ([org, stage]) => ({
        ma_to_chuc: orgId(`orgs/${org}/status.cert.pem`), ten: `${org} (DEMO)`,
        chung_thu: [{ sha256: await fingerprint(`orgs/${org}/vc-product.cert.pem`), muc_dich: 'vc' }, { sha256: await fingerprint(`orgs/${org}/status.cert.pem`), muc_dich: 'status' }],
        vct: [VCT.productEvent], cong_doan: [stage], ...validity,
      })))),
    ],
    verifiers: [{
      ma_to_chuc: orgId('orgs/nha-tuyen-dung-mau/request.cert.pem'), ten: 'Nhà Tuyển Dụng Mẫu (DEMO)',
      chung_thu: [{ sha256: await fingerprint('orgs/nha-tuyen-dung-mau/request.cert.pem'), muc_dich: 'request' }],
    }],
  };
  const trustListSigner = await createWebCryptoSigner({ privateKey: read('trust-list-signer/trust-list.key.pem'), x5c: certB64('trust-list-signer/trust-list.cert.pem') });
  const signTrustList = () => createTrustListToken({ ...trustContent, signer: trustListSigner, now: NOW });
  const trustToken = await signTrustList();

  // In-memory TrustRegistry (no I/O, no signature): fingerprint -> entry, from the same content.
  const entries = new Map();
  for (const i of trustContent.issuers) for (const c of i.chung_thu) entries.set(c.sha256, { maToChuc: i.ma_to_chuc, ten: i.ten, mucDich: c.muc_dich, vct: i.vct, congDoan: i.cong_doan });
  const memoryTrust = { async lookup(fp) { return entries.get(fp) ?? null; } };
  const memoryStatus = { async check() { return 'valid'; } };

  // --- status lists: truong-mau's has ~1% of its 131 072 entries set (revoked / suspended) --------
  const rand = mulberry32(20260101);
  const setIdx = new Set();
  while (setIdx.size < 1311) setIdx.add(Math.floor(rand() * 131_072));
  const fillList = () => {
    const l = createStatusList();
    for (const i of setIdx) l.setStatus(i, i % 2 === 0 ? 1 : 2);
    return l;
  };
  const bigList = fillList();
  let credIdx = 1000;
  while (setIdx.has(credIdx)) credIdx++; // the benchmarked credential is valid
  const statusSigner = await signer('truong-mau', 'status');
  const signStatusList = (list) => createStatusListToken({ list, uri: statusUri('truong-mau'), signer: statusSigner, now: NOW });
  const statusToken = await signStatusList(bigList);

  const routes = { [TRUST_URL]: trustToken, [statusUri('truong-mau')]: statusToken };
  for (const [org] of PRODUCT_ORGS) {
    routes[statusUri(org)] = await createStatusListToken({ list: createStatusList(), uri: statusUri(org), signer: await signer(org, 'status'), now: NOW });
  }
  // A fresh recording in-memory fetch: no socket, no latency; `calls` proves the caches are warm.
  const newFetch = () => {
    const calls = [];
    const fetch = async (url) => {
      calls.push(url);
      const body = routes[url];
      if (body === undefined) throw new Error(`no route ${url}`);
      return { status: 200, headers: { get: () => null }, text: async () => body };
    };
    return { fetch, calls };
  };
  /** Real signed-list registry and checker over a fresh in-memory fetch (empty caches). */
  const realLists = (backend) => {
    const { verifier, chainValidator } = backends[backend];
    const served = newFetch();
    const trustRegistry = createSignedTrustListRegistry({ url: TRUST_URL, fetch: served.fetch, verifier, chainValidator, clock });
    const statusChecker = createStatusListChecker({ fetch: served.fetch, verifier, chainValidator, trustRegistry, clock });
    return { trustRegistry, statusChecker, served };
  };

  // --- keys, credential, presentation -------------------------------------------------------------
  const vcSigner = await signer('truong-mau', 'vc');
  const vcX5c = certB64('orgs/truong-mau/vc.chain.pem');
  const holder = createNobleSigner(generateSecretKey(webCryptoRandom));
  const issue = () => issueDiploma({ signer: vcSigner, hasher: webCryptoHasher, random: webCryptoRandom, clock, iss: ISS, cnfJwk: holder.publicJwk, status: { idx: credIdx, uri: statusUri('truong-mau') }, claims: DIPLOMA });
  const credential = await issue();
  const nonce = base64UrlEncode(webCryptoRandom.bytes(16));
  const present = (hasher = nobleHasher) => createPresentation({ compact: credential, disclose: ['ho_ten', 'nganh'], holderSigner: holder, audience: AUDIENCE, nonce, now: NOW, hasher });
  const presentation = await present();
  const verifyOptions = (backend, lists) => ({
    ...backends[backend], trustRegistry: lists?.trustRegistry ?? memoryTrust, statusChecker: lists?.statusChecker ?? memoryStatus,
    supportedVcts: [VCT.diploma], now: NOW, presentation: { nonce, audience: AUDIENCE },
  });

  // --- product chain: three events, stage by stage, each linked to the previous one ----------------
  const TIMES = ['2026-01-02T08:00:00Z', '2026-01-03T09:30:00Z', '2026-01-05T15:00:00.250Z'];
  const events = [];
  for (const [i, [org, stage]] of PRODUCT_ORGS.entries()) {
    const prev = i === 0 ? {} : { prev: await productEventHash(events[i - 1], webCryptoHasher) };
    events.push(await issueProductEvent({
      signer: await signer(org, 'vc-product'), hasher: webCryptoHasher, random: webCryptoRandom, clock: { now: () => new Date(NOW.getTime() - 600_000) },
      iss: `${ORIGIN}/issuers/${org}`, status: { idx: 10 + i, uri: statusUri(org) },
      claims: { ma_san_pham: `(01)${GTIN}(21)${SERIAL}`, cong_doan: stage, thoi_diem: TIMES[i], dia_diem: `Kho ${i + 1}`, mo_ta: `Công đoạn ${i + 1}`, ...prev },
    }));
  }

  return {
    NOW, clock, backends, trustContent, trustToken, statusToken, signTrustList, signStatusList, fillList, statusSigner, credIdx, issue, present, credential, presentation, holder,
    vcX5c, memoryTrust, memoryStatus, realLists, verifyOptions, events, productOptions: (lists) => ({ ...backends.webcrypto, trustRegistry: lists.trustRegistry, statusChecker: lists.statusChecker, now: NOW }),
    setCount: setIdx.size,
  };
}
