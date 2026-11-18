// Fixtures for the SD-JWT VC tests: issuer and holder keys from the test PKI, in-memory trust
// and status fakes, and hand-crafting of adversarial credentials.
import { createHash } from 'node:crypto';
import {
  base64UrlEncode,
  createCertificateChainValidator,
  utf8Encode,
  VCT,
  type CheckId,
  type CredentialVerificationResult,
  type DiplomaClaims,
  type Signer,
  type StatusChecker,
  type TrustEntry,
  type TrustRegistry,
  type VerifyCredentialOptions,
} from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { ca, leaf, NOW, pemFile, x5c } from './pki.js';

export const ISS = 'https://api-identra.awncorp.vn/issuers/truong-mau';
export const STATUS = { idx: 42, uri: `${ISS}/status/1` };
export const AUD = 'x509_hash:verifier-under-test';
export const NONCE = 'nonce-0S6_WzA2Mj';
export const NOW_S = NOW.getTime() / 1000;
export const clock = { now: () => NOW };
export const DIPLOMA: DiplomaClaims = {
  ho_ten: 'Nguyễn Văn A',
  ngay_sinh: '2001-02-03',
  ma_sinh_vien: 'SV123456',
  nganh: 'Khoa học máy tính',
  hang_tot_nghiep: 'Giỏi',
  nam_tot_nghiep: '2024',
  so_hieu_bang: 'B-0001',
};

export const fingerprintOf = (der: Uint8Array) => createHash('sha256').update(der).digest('base64url');
export const VC_FINGERPRINT = fingerprintOf(leaf('vc'));

export const issuerSigner = (name = 'vc', caName = 'issuing') =>
  createWebCryptoSigner({ privateKey: pemFile(`test/leaf/${name}.key.pem`), x5c: x5c(name, caName) });

export async function holderKey(): Promise<Signer> {
  const { privateKey } = await generateWebCryptoKeyPair();
  return createWebCryptoSigner({ privateKey });
}

export const issuerContext = async () => ({ signer: await issuerSigner(), hasher: webCryptoHasher, random: webCryptoRandom, clock });

export const TRUST_ENTRY: TrustEntry = {
  maToChuc: 'VATVN-0100000001',
  ten: 'Trường Mẫu TEST',
  mucDich: 'vc',
  vct: [VCT.diploma, VCT.productEvent],
  congDoan: ['san_xuat'],
};

/** Answers `entry` for the vc leaf fingerprint only; or throws `entry` when it is an Error. */
export function fakeTrust(entry: TrustEntry | null | Error = TRUST_ENTRY, fingerprint = VC_FINGERPRINT): TrustRegistry & { calls: number } {
  const fake = {
    calls: 0,
    async lookup(fp: string) {
      fake.calls++;
      if (entry instanceof Error) throw entry;
      return fp === fingerprint ? entry : null;
    },
  };
  return fake;
}

export function fakeStatus(answer: Awaited<ReturnType<StatusChecker['check']>> | Error = 'valid'): StatusChecker & { calls: number } {
  const fake = {
    calls: 0,
    async check() {
      fake.calls++;
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
  return fake;
}

export const validator = createCertificateChainValidator({ trustedRoots: [ca('root')], verifier: webCryptoVerifier, hasher: webCryptoHasher });

export function verifyOptions(overrides: Partial<VerifyCredentialOptions> = {}): VerifyCredentialOptions {
  return {
    verifier: webCryptoVerifier,
    hasher: webCryptoHasher,
    chainValidator: validator,
    trustRegistry: fakeTrust(),
    statusChecker: fakeStatus(),
    supportedVcts: [VCT.diploma, VCT.productEvent],
    now: NOW,
    ...overrides,
  };
}
export const presentationOptions = (overrides: Partial<VerifyCredentialOptions> = {}) =>
  verifyOptions({ presentation: { nonce: NONCE, audience: AUD }, ...overrides });

export function check(result: CredentialVerificationResult, id: CheckId) {
  const c = result.checks.find((x) => x.id === id);
  if (!c) throw new Error(`check ${id} not listed`);
  return c;
}
/** [id, code] of every listed check. */
export const codes = (result: CredentialVerificationResult) => result.checks.map((c) => [c.id, c.code]);

const b64json = (v: unknown) => base64UrlEncode(utf8Encode(JSON.stringify(v)));
export const disclosure = (name: string, value: unknown, salt = base64UrlEncode(webCryptoRandom.bytes(16))) => b64json([salt, name, value]);
export const digestOf = async (encoded: string) => base64UrlEncode(await webCryptoHasher.sha256(utf8Encode(encoded)));

/** Signs header.payload with `signer` exactly as given: no defaults, no checks. */
export async function rawJws(header: Record<string, unknown>, payload: Record<string, unknown>, signer: Signer): Promise<string> {
  const input = `${b64json(header)}.${b64json(payload)}`;
  return `${input}.${base64UrlEncode(await signer.sign(utf8Encode(input)))}`;
}

export function visiblePayload(cnfJwk?: unknown): Record<string, unknown> {
  return {
    iss: ISS,
    vct: VCT.diploma,
    iat: NOW_S - 3600,
    ...(cnfJwk ? { cnf: { jwk: cnfJwk } } : {}),
    status: { status_list: { idx: STATUS.idx, uri: STATUS.uri } },
  };
}

/**
 * A hand-made issuer-signed SD-JWT: `disclosures` are encoded disclosure strings whose digests go
 * into `_sd` (plus `extraDigests`). `header` and `payload` replace the defaults key by key.
 */
export async function craft(options: {
  payload?: Record<string, unknown>;
  header?: Record<string, unknown>;
  disclosures?: string[];
  referenced?: string[];
  extraDigests?: string[];
  sdAlg?: unknown;
  signer?: Signer;
}): Promise<string> {
  const signer = options.signer ?? (await issuerSigner());
  const disclosures = options.disclosures ?? [];
  const referenced = options.referenced ?? disclosures;
  const sd = [...(await Promise.all(referenced.map(digestOf))), ...(options.extraDigests ?? [])].sort();
  const payload = { ...(options.payload ?? visiblePayload()), ...(sd.length ? { _sd: sd, _sd_alg: options.sdAlg ?? 'sha-256' } : {}) };
  const header = { alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c ?? x5c('vc'), ...options.header };
  return `${await rawJws(header, payload, signer)}~${disclosures.map((d) => `${d}~`).join('')}`;
}

/** Appends a KB-JWT to an SD-JWT ending with "~"; every field can be overridden. */
export async function addKb(
  sdJwt: string,
  holder: Signer,
  options: { header?: Record<string, unknown>; payload?: Record<string, unknown> } = {},
): Promise<string> {
  const sdHash = base64UrlEncode(await webCryptoHasher.sha256(utf8Encode(sdJwt)));
  const payload = { iat: Math.floor(NOW_S), aud: AUD, nonce: NONCE, sd_hash: sdHash, ...options.payload };
  return sdJwt + (await rawJws({ typ: 'kb+jwt', alg: 'ES256', ...options.header }, payload, holder));
}
