// Fixtures for the status list and trust list tests: signers and fingerprints from the test PKI,
// a demo-like trust list, a fake clock and a scripted fake fetch that counts its calls.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSignedTrustListRegistry, createTrustListToken, VCT, type Clock, type HttpFetch, type Signer, type TrustListContent } from '@identra/sdk-core';
import { createWebCryptoSigner, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { b64, leaf, NOW, pemCerts, pemFile, REPO, x5c } from './pki.js';
import { fingerprintOf, validator } from './sdjwt.js';

export const TRUST_URL = 'https://api-identra.awncorp.vn/trust-list';
export const ORG = { truongMau: 'VATVN-0100000001', nhaSanXuat: 'VATVN-0100000002', nhaTuyenDung: 'VATVN-0100000005' };

export const statusSigner = (name = 'status', caName = 'issuing') =>
  createWebCryptoSigner({ privateKey: pemFile(`test/leaf/${name}.key.pem`), x5c: x5c(name, caName) });
export const trustListSigner = () => createWebCryptoSigner({ privateKey: pemFile('test/leaf/trust-list.key.pem'), x5c: [b64(leaf('trust-list'))] });

let other: { signer: Signer; fingerprint: string } | undefined;
/**
 * A `status` certificate of ANOTHER organisation (Nha San Xuat TEST, VATVN-0100000002), issued by
 * the real test Issuing CA through identra-pki.sh on a copy of the CA directory, so that the shared
 * test PKI is not modified.
 */
export async function otherOrgStatus(): Promise<{ signer: Signer; fingerprint: string }> {
  if (other) return other;
  const dir = mkdtempSync(join(tmpdir(), 'identra-other-status-'));
  cpSync(fileURLToPath(new URL('.pki/test/ca/issuing', REPO)), join(dir, 'issuing'), { recursive: true });
  const pki = (...args: string[]) => execFileSync('bash', [fileURLToPath(new URL('scripts/pki/identra-pki.sh', REPO)), ...args], { stdio: 'pipe' });
  const [key, csr, cert, chain] = ['status.key.pem', 'status.csr.pem', 'status.cert.pem', 'status.chain.pem'].map((f) => join(dir, f)) as [string, string, string, string];
  pki('new-key-and-csr', '--key', key, '--csr', csr, '--o', 'Nha San Xuat TEST', '--mst', '0100000002', '--cn', 'Nha San Xuat TEST (status)');
  pki('issue-leaf', '--ca-dir', join(dir, 'issuing'), '--csr', csr, '--purpose', 'status', '--out', cert, '--chain', chain, '--start', '20260101000000Z');
  const ders = pemCerts(readFileSync(chain, 'utf8'));
  other = { signer: await createWebCryptoSigner({ privateKey: readFileSync(key, 'utf8'), x5c: ders.map(b64) }), fingerprint: fingerprintOf(ders[0]!) };
  return other;
}

let later: Signer | undefined;
/**
 * A second trust-list signer, issued directly by the test root with notBefore 2026-03-01 (the
 * first one starts 2026-01-01): the replacement after a key compromise (ADR-0019 section 2).
 * Made with identra-pki.sh on a copy of the root directory.
 */
export async function laterTrustListSigner(): Promise<Signer> {
  if (later) return later;
  const dir = mkdtempSync(join(tmpdir(), 'identra-later-tl-'));
  cpSync(fileURLToPath(new URL('.pki/test/ca/root', REPO)), join(dir, 'root'), { recursive: true });
  const pki = (...args: string[]) => execFileSync('bash', [fileURLToPath(new URL('scripts/pki/identra-pki.sh', REPO)), ...args], { stdio: 'pipe' });
  const [key, csr, cert] = ['tl.key.pem', 'tl.csr.pem', 'tl.cert.pem'].map((f) => join(dir, f)) as [string, string, string];
  pki('new-key-and-csr', '--key', key, '--csr', csr, '--o', 'Identra TEST', '--mst', '0100000000', '--cn', 'Identra TEST Trust List Signer 2');
  pki('issue-trust-list-signer', '--root-dir', join(dir, 'root'), '--csr', csr, '--out', cert, '--start', '20260301000000Z');
  later = await createWebCryptoSigner({ privateKey: readFileSync(key, 'utf8'), x5c: pemCerts(readFileSync(cert, 'utf8')).map(b64) });
  return later;
}
export const LATER_SIGNER_NOT_BEFORE = Date.UTC(2026, 2, 1) / 1000;

export const FP = {
  vc: fingerprintOf(leaf('vc')),
  status: fingerprintOf(leaf('status')),
  vcProduct: fingerprintOf(leaf('vc-product')),
  request: fingerprintOf(leaf('request')),
};

/** Truong Mau (vc + status), Nha San Xuat (vc-product + the other-organisation status), Nha Tuyen Dung (request). */
export async function demoContent(): Promise<TrustListContent> {
  const { fingerprint } = await otherOrgStatus();
  return {
    issuers: [
      {
        ma_to_chuc: ORG.truongMau, ten: 'Trường Mẫu (TEST)',
        chung_thu: [{ sha256: FP.vc, muc_dich: 'vc' }, { sha256: FP.status, muc_dich: 'status' }],
        vct: [VCT.diploma], validFrom: '2026-01-01T00:00:00Z', validUntil: '2029-01-01T00:00:00Z',
      },
      {
        ma_to_chuc: ORG.nhaSanXuat, ten: 'Nhà Sản Xuất (TEST)',
        chung_thu: [{ sha256: FP.vcProduct, muc_dich: 'vc' }, { sha256: fingerprint, muc_dich: 'status' }],
        vct: [VCT.productEvent], cong_doan: ['san_xuat'], validFrom: '2026-01-01T00:00:00Z', validUntil: '2029-01-01T00:00:00Z',
      },
    ],
    verifiers: [{ ma_to_chuc: ORG.nhaTuyenDung, ten: 'Nhà Tuyển Dụng Mẫu (TEST)', chung_thu: [{ sha256: FP.request, muc_dich: 'request' }] }],
  };
}

export function fakeClock(start = NOW) {
  let t = start.getTime();
  return { now: () => new Date(t), advance: (seconds: number) => void (t += seconds * 1000) };
}

export type Route = { status: number; body: string } | Error;
/**
 * A fetch answering from `routes` (URL -> answer, or a function giving the answer, possibly later);
 * an Error answer and an unknown URL reject like an unreachable host. Every call is recorded.
 */
export function scriptedFetch(routes: Record<string, Route | (() => Route | Promise<Route>)>) {
  const calls: { url: string; timeoutMs: number | undefined; maxBytes?: number | undefined }[] = [];
  const fetch: HttpFetch = async (url, init) => {
    calls.push({ url, timeoutMs: init?.timeoutMs, maxBytes: init?.maxBytes });
    const route = routes[url];
    if (route === undefined) throw new Error('host unreachable');
    const r = typeof route === 'function' ? await route() : route;
    if (r instanceof Error) throw r;
    return { status: r.status, headers: { get: () => null }, text: async () => r.body };
  };
  return { fetch, calls, routes };
}
export const ok = (body: string) => ({ status: 200, body });

/** A signed trust list token of `content` (default demoContent) by the test trust-list signer. */
export async function trustToken(
  content?: TrustListContent,
  now = NOW,
  options: { ttlSeconds?: number; lifetimeSeconds?: number; signer?: Signer; signerNotBefore?: number } = {},
) {
  return createTrustListToken({ ...(content ?? (await demoContent())), signer: await trustListSigner(), now, ...options });
}

/** The real registry, fed by a scripted fetch that serves `token` at TRUST_URL. */
export async function servedRegistry(token?: string, clock: Clock = fakeClock()) {
  const served = scriptedFetch({ [TRUST_URL]: ok(token ?? (await trustToken())) });
  const registry = createSignedTrustListRegistry({ url: TRUST_URL, fetch: served.fetch, verifier: webCryptoVerifier, chainValidator: validator, clock });
  return { registry, ...served };
}
