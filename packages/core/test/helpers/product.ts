// A product-chain world from the DEMO PKI (.pki/demo, made by ensure-test-pki.sh): the three product
// organisations with their vc-product and status certificates, a trust list with their cong_doan
// scopes, one status list per organisation, all served by a recording in-memory fetch, and the real
// trust registry and status checker on top. Time is fixed one hour after the newest certificate.
import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  base64Encode,
  createSignedTrustListRegistry,
  createStatusList,
  createStatusListChecker,
  createCertificateChainValidator,
  createStatusListToken,
  createTrustListToken,
  issueProductEvent,
  parseCertificate,
  productEventHash,
  VCT,
  type CongDoan,
  type ProductEventClaims,
  type Signer,
  type StatusList,
  type StatusValue,
  type TrustListIssuer,
  type VerifyProductChainOptions,
} from '@identra/sdk-core';
import { createWebCryptoSigner, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { extRest, forge, withExtension } from './forge.js';
import { ok, scriptedFetch, TRUST_URL } from './lists.js';
import { pemCerts, REPO } from './pki.js';
import { fingerprintOf, rawJws } from './sdjwt.js';

export const DEMO = new URL('.pki/demo/', REPO);
export const ORGS = ['nha-san-xuat', 'kiem-dinh', 'phan-phoi'] as const;
export type Org = (typeof ORGS)[number];
export const STAGE: Record<Org, CongDoan> = { 'nha-san-xuat': 'san_xuat', 'kiem-dinh': 'kiem_dinh', 'phan-phoi': 'phan_phoi' };
export const GTIN = '09520123456788';
export const SERIAL = 'SN-0001';
export const CODE = `(01)${GTIN}(21)${SERIAL}`;
export const issOf = (org: string) => `https://api-identra.awncorp.vn/issuers/${org}`;
export const statusUriOf = (org: string) => `${issOf(org)}/status/1`;
export const TIMES = ['2026-01-02T08:00:00Z', '2026-01-03T09:30:00Z', '2026-01-05T15:00:00.250Z'];

export const demoCerts = (path: string) => pemCerts(readFileSync(new URL(path, DEMO), 'utf8'));
export const demoRoot = (): Uint8Array => demoCerts('root.cert.pem')[0]!;
const files = [...ORGS.flatMap((o) => [`orgs/${o}/vc-product.cert.pem`, `orgs/${o}/status.cert.pem`]), 'trust-list-signer/trust-list.cert.pem'];
/** One hour after the newest certificate's notBefore: every demo certificate is valid then. */
export const PRODUCT_NOW = new Date(Math.max(...files.map((f) => parseCertificate(demoCerts(f)[0]!).notBefore.getTime())) + 3600_000);

export const demoSigner = (org: string, purpose: 'vc' | 'vc-product' | 'status'): Promise<Signer> =>
  createWebCryptoSigner({
    privateKey: readFileSync(new URL(`orgs/${org}/${purpose}.key.pem`, DEMO), 'utf8'),
    x5c: demoCerts(`orgs/${org}/${purpose}.chain.pem`).map(base64Encode),
  });

/** The trust list entry of a product organisation; `congDoan` overrides its scope. */
export function trustIssuer(org: Org, congDoan: CongDoan[] = [STAGE[org]]): TrustListIssuer {
  const fp = (purpose: string) => fingerprintOf(demoCerts(`orgs/${org}/${purpose}.cert.pem`)[0]!);
  const day = 86400_000;
  return {
    ma_to_chuc: parseCertificate(demoCerts(`orgs/${org}/status.cert.pem`)[0]!).subject.organizationIdentifier!,
    ten: `${org} (DEMO)`,
    chung_thu: [{ sha256: fp('vc-product'), muc_dich: 'vc' }, { sha256: fp('status'), muc_dich: 'status' }],
    vct: [VCT.productEvent],
    cong_doan: congDoan,
    validFrom: new Date(PRODUCT_NOW.getTime() - day).toISOString(),
    validUntil: new Date(PRODUCT_NOW.getTime() + 3650 * day).toISOString(),
  };
}

export type EventClaims = Partial<ProductEventClaims>;

export async function productWorld(o: { issuers?: TrustListIssuer[] } = {}) {
  const now = PRODUCT_NOW;
  const clock = { now: () => now };
  const trustListSigner = await createWebCryptoSigner({
    privateKey: readFileSync(new URL('trust-list-signer/trust-list.key.pem', DEMO), 'utf8'),
    x5c: demoCerts('trust-list-signer/trust-list.cert.pem').map(base64Encode),
  });
  const trustList = await createTrustListToken({ issuers: o.issuers ?? ORGS.map((org) => trustIssuer(org)), verifiers: [], signer: trustListSigner, now });
  const served = scriptedFetch({ [TRUST_URL]: ok(trustList) });
  const lists = new Map<string, StatusList>(ORGS.map((org) => [org, createStatusList()]));
  const chainValidator = createCertificateChainValidator({ trustedRoots: [demoRoot()], verifier: webCryptoVerifier, hasher: webCryptoHasher });

  /** (Re)signs the status list tokens; call after setStatus and before the first verification. */
  async function publish() {
    for (const org of ORGS) {
      served.routes[statusUriOf(org)] = ok(await createStatusListToken({ list: lists.get(org)!, uri: statusUriOf(org), signer: await demoSigner(org, 'status'), now }));
    }
  }
  await publish();

  /** Real registry and checker over the recording fetch; a new set has empty caches. */
  function options(): VerifyProductChainOptions {
    const trustRegistry = createSignedTrustListRegistry({ url: TRUST_URL, fetch: served.fetch, verifier: webCryptoVerifier, chainValidator, clock });
    const statusChecker = createStatusListChecker({ fetch: served.fetch, verifier: webCryptoVerifier, chainValidator, trustRegistry, clock });
    return { verifier: webCryptoVerifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, now };
  }

  /** The event of stage `index` (0-2) by its organisation, linked to `previous`; claims override. */
  async function issue(index: number, previous: string | undefined, claims: EventClaims = {}, org: Org = ORGS[index]!) {
    const prev = previous === undefined ? {} : { prev: await productEventHash(previous, webCryptoHasher) };
    return issueProductEvent({
      signer: await demoSigner(org, 'vc-product'), hasher: webCryptoHasher, random: webCryptoRandom, clock: { now: () => new Date(now.getTime() - 600_000) },
      iss: issOf(org), status: { idx: 10 + index, uri: statusUriOf(org) },
      claims: { ma_san_pham: CODE, cong_doan: STAGE[ORGS[index]!], thoi_diem: TIMES[index]!, dia_diem: `Kho ${index + 1}`, mo_ta: `Công đoạn ${index + 1}`, ...prev, ...claims },
    });
  }

  /** The first `n` events of a correctly linked chain. */
  async function chain(n = 3): Promise<string[]> {
    const events: string[] = [];
    for (let i = 0; i < n; i++) events.push(await issue(i, events[i - 1]));
    return events;
  }

  /** An event signed by `org` exactly as given, bypassing the issuer's checks (a foreign issuer). */
  async function craft(org: Org, payload: Record<string, unknown>): Promise<string> {
    const signer = await demoSigner(org, 'vc-product');
    const base = { iss: issOf(org), vct: VCT.productEvent, iat: Math.floor(now.getTime() / 1000) - 600, status: { status_list: { idx: 7, uri: statusUriOf(org) } } };
    return `${await rawJws({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c }, { ...base, ...payload }, signer)}~`;
  }

  return {
    now, root: demoRoot(), trustList, served, options, issue, chain, craft, publish,
    setStatus: (org: Org, idx: number, value: StatusValue) => lists.get(org)!.setStatus(idx, value),
    /** URLs fetched so far. */
    urls: () => served.calls.map((c) => c.url),
  };
}

/**
 * The nha-san-xuat vc-product leaf re-issued by the demo Issuing CA with the SAN URI `iss` (another
 * host), its fingerprint added to the organisation's trust list entry, and a first-stage event it
 * signs with `iss` and a status list under `iss`: a trusted certificate pointing elsewhere.
 */
export async function foreignSanIssuer(iss = 'https://evil.example/issuers/nha-san-xuat') {
  const [leaf, issuing] = demoCerts('orgs/nha-san-xuat/vc-product.chain.pem') as [Uint8Array, Uint8Array];
  const uri = [...new TextEncoder().encode(iss)];
  const caKey = createPrivateKey(readFileSync(new URL('ca/issuing/ca.key.pem', DEMO), 'utf8'));
  const forged = forge(leaf, (tbs) => withExtension(tbs, 'subjectAltName', extRest(false, [0x30, uri.length + 2, 0x86, uri.length, ...uri])), caKey);
  const entry = trustIssuer('nha-san-xuat');
  entry.chung_thu.push({ sha256: fingerprintOf(forged), muc_dich: 'vc' });
  const signer = await createWebCryptoSigner({
    privateKey: readFileSync(new URL('orgs/nha-san-xuat/vc-product.key.pem', DEMO), 'utf8'),
    x5c: [base64Encode(forged), base64Encode(issuing)],
  });
  const payload = {
    iss, vct: VCT.productEvent, iat: Math.floor(PRODUCT_NOW.getTime() / 1000) - 600, status: { status_list: { idx: 3, uri: `${iss}/status/1` } },
    ma_san_pham: CODE, cong_doan: 'san_xuat', thoi_diem: TIMES[0], dia_diem: 'd', mo_ta: 'm',
  };
  return { entry, event: `${await rawJws({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c }, payload, signer)}~` };
}
