// SD-JWT VC issuance (ADR-0001, ADR-0008, ADR-0015 section 4). Input mistakes are programmer
// errors and throw TypeError; nothing is signed unless the whole input is valid.
import { base64Decode } from '../encoding.js';
import type { Clock, EcPublicJwk, Hasher, RandomSource, Signer } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { parseCertificate } from '../x509/parse.js';
import {
  CONG_DOAN,
  DIPLOMA_CLAIMS,
  DIPLOMA_SD_DIGESTS,
  METADATA_CLAIMS,
  PRODUCT_EVENT_CLAIMS,
  RESERVED_CLAIM_NAMES,
  SD_JWT_LIMITS,
  VCT,
  type DiplomaClaims,
  type ProductEventClaims,
} from './credential-types.js';
import { libIssue } from './library.js';

export interface IssuerContext {
  /** ES256 signer whose `x5c` is [leaf, issuing CA] and whose leaf has `iss` as a SAN URI. */
  signer: Signer;
  hasher: Hasher;
  random: RandomSource;
  clock: Clock;
}

export interface IssueCredentialInput extends IssuerContext {
  /** HTTPS issuer URL. */
  iss: string;
  vct: string;
  /** NumericDate seconds. */
  nbf?: number;
  exp?: number;
  cnfJwk?: EcPublicJwk;
  /** `uri` must be `<iss>/status/...` (ADR-0015 section 11). */
  status: { idx: number; uri: string };
  /** Subject claims. */
  claims: Record<string, unknown>;
  /** Names of subject claims made selectively disclosable, each as its own top-level disclosure. */
  disclosable: string[];
  /** Total number of `_sd` digests (real plus decoys); only with disclosable claims. */
  sdDigests?: number;
}

function fail(message: string): never {
  throw new TypeError(message);
}
const has = (o: object, name: string): boolean => Object.keys(o).includes(name);
const isNumericDate = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

function checkSigner(signer: Signer, iss: string): Signer & { x5c: string[] } {
  if (signer?.alg !== 'ES256' || typeof signer.sign !== 'function') fail('signer must be an ES256 Signer');
  const x5c = signer.x5c;
  if (!Array.isArray(x5c) || x5c.length !== 2 || !x5c.every((c) => typeof c === 'string')) {
    fail('issuer signer must carry x5c [leaf, issuing CA]');
  }
  const leaf = parseCertificate(base64Decode(x5c![0]!));
  if (!leaf.sanUris.includes(iss)) fail('iss is not a SAN URI of the signer certificate');
  return signer as Signer & { x5c: string[] };
}

/** Generic issuance; prefer issueDiploma / issueProductEvent. Returns the compact, ending with "~". */
export async function issueCredential(input: IssueCredentialInput): Promise<string> {
  const { hasher, random, clock, iss, vct, nbf, exp, cnfJwk, status, claims, disclosable, sdDigests } = input;
  if (typeof iss !== 'string' || !iss.startsWith('https://')) fail('iss must be an https URL');
  const signer = checkSigner(input.signer, iss);
  if (typeof vct !== 'string' || vct === '') fail('vct must be a non-empty string');
  if (nbf !== undefined && !isNumericDate(nbf)) fail('nbf must be a NumericDate');
  if (exp !== undefined && !isNumericDate(exp)) fail('exp must be a NumericDate');
  if (!Number.isSafeInteger(status?.idx) || status.idx < 0) fail('status.idx must be a non-negative integer');
  if (typeof status.uri !== 'string' || !status.uri.startsWith(`${iss}/status/`)) fail('status.uri must start with <iss>/status/');
  if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) fail('claims must be an object');
  if (!Array.isArray(disclosable) || new Set(disclosable).size !== disclosable.length) fail('disclosable must be a list of distinct names');
  for (const name of disclosable) if (METADATA_CLAIMS.includes(name)) fail(`metadata claim ${name} can never be disclosable`);
  for (const name of Object.keys(claims)) {
    if (METADATA_CLAIMS.includes(name) || RESERVED_CLAIM_NAMES.includes(name)) fail(`${name} is not a subject claim name`);
  }
  for (const name of disclosable) if (!has(claims, name)) fail(`disclosable claim ${name} is not among the subject claims`);
  let decoys = 0;
  if (sdDigests !== undefined) {
    if (disclosable.length === 0 || !Number.isSafeInteger(sdDigests) || sdDigests < disclosable.length) {
      fail('sdDigests must be an integer at least the number of disclosable claims');
    }
    decoys = sdDigests - disclosable.length;
  }
  let jwk: EcPublicJwk | null = null;
  if (cnfJwk !== undefined && !(jwk = normalizeEcPublicJwk(cnfJwk))) fail('cnfJwk must be an EC P-256 public JWK');
  const now = clock.now();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail('clock.now() must return a valid Date');

  const payload: Record<string, unknown> = { iss, vct, iat: Math.floor(now.getTime() / 1000) };
  if (nbf !== undefined) payload['nbf'] = nbf;
  if (exp !== undefined) payload['exp'] = exp;
  if (jwk) payload['cnf'] = { jwk };
  payload['status'] = { status_list: { idx: status.idx, uri: status.uri } };
  Object.assign(payload, claims);
  return libIssue({ signer, hasher, random, payload, disclosable, decoys });
}

function exactKeys(claims: object, required: readonly string[], optional: readonly string[] = []): void {
  if (typeof claims !== 'object' || claims === null) fail('claims must be an object');
  for (const name of required) if (!has(claims, name)) fail(`missing claim ${name}`);
  for (const name of Object.keys(claims)) if (!required.includes(name) && !optional.includes(name)) fail(`unexpected claim ${name}`);
}

/** Diploma: seven disclosable subject claims, `_sd` padded to 10 digests, holder binding, no `exp`. */
export async function issueDiploma(
  input: IssuerContext & { iss: string; cnfJwk: EcPublicJwk; status: { idx: number; uri: string }; claims: DiplomaClaims },
): Promise<string> {
  exactKeys(input.claims, DIPLOMA_CLAIMS);
  for (const name of DIPLOMA_CLAIMS) {
    const v = input.claims[name];
    if (typeof v !== 'string' || v === '') fail(`${name} must be a non-empty string`);
  }
  if (input.cnfJwk === undefined) fail('a diploma requires cnfJwk');
  const { signer, hasher, random, clock, iss, cnfJwk, status, claims } = input;
  return issueCredential({
    signer, hasher, random, clock, iss, cnfJwk, status,
    vct: VCT.diploma,
    claims: { ...claims },
    disclosable: [...DIPLOMA_CLAIMS],
    sdDigests: DIPLOMA_SD_DIGESTS,
  });
}

const GS1_ELEMENT_STRING = /^\(01\)\d{14}\(21\)[!-~]{1,20}$/;
const SHA256_BASE64URL = /^[A-Za-z0-9_-]{43}$/;

/** Product lifecycle event: every claim visible, no disclosures, no `cnf`, no `exp`. */
export async function issueProductEvent(
  input: IssuerContext & { iss: string; status: { idx: number; uri: string }; claims: ProductEventClaims },
): Promise<string> {
  if ('cnfJwk' in input) fail('a product event has no holder binding (cnfJwk)');
  const claims = input.claims;
  exactKeys(claims, PRODUCT_EVENT_CLAIMS, ['prev']);
  for (const name of [...PRODUCT_EVENT_CLAIMS, 'prev'] as const) {
    const v = claims[name];
    if (v === undefined && name === 'prev') continue;
    if (typeof v !== 'string' || v === '' || v.length > SD_JWT_LIMITS.maxProductStringLength) {
      fail(`${name} must be a non-empty string of at most ${SD_JWT_LIMITS.maxProductStringLength} characters`);
    }
  }
  if (!GS1_ELEMENT_STRING.test(claims.ma_san_pham)) fail('ma_san_pham must be a GS1 element string (01)<GTIN>(21)<serial>');
  if (!CONG_DOAN.includes(claims.cong_doan)) fail(`cong_doan must be one of ${CONG_DOAN.join(', ')}`);
  if (claims.prev !== undefined && !SHA256_BASE64URL.test(claims.prev)) fail('prev must be base64url of a SHA-256 digest');
  const { signer, hasher, random, clock, iss, status } = input;
  return issueCredential({ signer, hasher, random, clock, iss, status, vct: VCT.productEvent, claims: { ...claims }, disclosable: [] });
}
