// The verification policy (docs/architecture.md section 3, ADR-0007, ADR-0015 section 7).
// Never throws for bad input; throws TypeError only for missing or wrong options.
import type { CertificateChainValidator, EcPublicJwk, Hasher, StatusChecker, TrustEntry, TrustRegistry, Verifier } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { checkJwsAlgorithm, verifyJwsSignature } from '../jws.js';
import { ErrorCodes, TrustListUnavailableError, type Check, type CheckId, type ErrorCode, type VerificationResult } from '../results.js';
import type { ParsedCertificate } from '../x509/parse.js';
import { parseSdJwt, type ParsedSdJwt } from './compact.js';
import { METADATA_CLAIMS, SD_JWT_LIMITS, VCT } from './credential-types.js';
import { checkHolderBinding } from './holder-binding.js';

export interface VerifyCredentialOptions {
  verifier: Verifier;
  hasher: Hasher;
  /** Pinned to the Identra root(s); used with profile `vc` and expectedIssuerUri = `iss`. */
  chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry;
  statusChecker: StatusChecker;
  supportedVcts: readonly string[];
  now: Date;
  /** Given when verifying a presentation: a KB-JWT with this nonce and audience is required. */
  presentation?: { nonce: string; audience: string };
}

export interface VerifiedCredential {
  vct: string;
  iss: string;
  /** base64url SHA-256 of the issuer leaf certificate. */
  fingerprint: string;
  /** From the trust list; null unless the issuer_trust check passed. */
  issuer: { maToChuc: string; ten: string } | null;
  iat: number;
  nbf?: number;
  exp?: number;
  status?: { idx: number; uri: string };
  cnfJwk?: EcPublicJwk;
  /** Subject claims (visible plus verified disclosures); only when holder_binding passed or is not listed. */
  claims?: Record<string, unknown>;
}

export interface CredentialVerificationResult extends VerificationResult {
  /** The steps of certificate chain validation, without detail strings. */
  chainChecks?: Check[];
  /** Only when the checks structure, algorithm, certificate_chain and signature passed. */
  credential?: VerifiedCredential;
}

class Failure {
  constructor(
    readonly code: ErrorCode,
    readonly detail: string,
  ) {}
}
const GATED: CheckId[] = ['structure', 'algorithm', 'certificate_chain', 'signature'];
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

function checkOptions(o: VerifyCredentialOptions): void {
  const fns: [unknown, string][] = [
    [o?.verifier?.verify, 'verifier'],
    [o?.hasher?.sha256, 'hasher'],
    [o?.chainValidator?.validate, 'chainValidator'],
    [o?.trustRegistry?.lookup, 'trustRegistry'],
    [o?.statusChecker?.check, 'statusChecker'],
  ];
  for (const [fn, name] of fns) if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  if (!Array.isArray(o.supportedVcts)) throw new TypeError('supportedVcts must be an array');
  if (!(o.now instanceof Date) || Number.isNaN(o.now.getTime())) throw new TypeError('now must be a valid Date');
  const p = o.presentation;
  if (p !== undefined && (typeof p.nonce !== 'string' || p.nonce === '' || typeof p.audience !== 'string' || p.audience === '')) {
    throw new TypeError('presentation needs a non-empty nonce and audience');
  }
}

// Step 1: compact form, typ, sizes, and the shape (not the truth) of the metadata claims.
function checkStructure(compact: unknown, presentation: boolean): ParsedSdJwt {
  const parsed = parseSdJwt(compact);
  if (!parsed.ok) throw new Failure(parsed.code, parsed.detail);
  const { jws, payload, kbJwt } = parsed.sdJwt;
  if (jws.header['typ'] !== 'dc+sd-jwt') throw new Failure(ErrorCodes.TYP_INVALID, 'typ is not dc+sd-jwt');
  if (kbJwt !== null && !presentation) throw new Failure(ErrorCodes.MALFORMED, 'a stored credential carries no KB-JWT');
  const p = payload;
  const shapeOk =
    typeof p['iss'] === 'string' && typeof p['vct'] === 'string' && isTime(p['iat']) &&
    (p['nbf'] === undefined || isTime(p['nbf'])) && (p['exp'] === undefined || isTime(p['exp'])) &&
    (p['cnf'] === undefined || isObject(p['cnf'])) && (p['status'] === undefined || isObject(p['status']));
  if (!shapeOk) throw new Failure(ErrorCodes.MALFORMED, 'payload lacks string iss / vct, numeric iat, or has mistyped metadata');
  return parsed.sdJwt;
}

function checkValidityTime(p: Record<string, unknown>, now: Date): void {
  const t = now.getTime() / 1000;
  const skew = SD_JWT_LIMITS.clockSkewSeconds;
  if ((p['iat'] as number) > t + skew) throw new Failure(ErrorCodes.NOT_YET_VALID, 'iat is in the future');
  if (isTime(p['nbf']) && p['nbf'] > t + skew) throw new Failure(ErrorCodes.NOT_YET_VALID, 'nbf is in the future');
  if (isTime(p['exp']) && p['exp'] <= t - skew) throw new Failure(ErrorCodes.EXPIRED, 'exp has passed');
}

async function checkIssuerTrust(o: VerifyCredentialOptions, fingerprint: string, leaf: ParsedCertificate, p: Record<string, unknown>): Promise<TrustEntry> {
  const untrusted = (detail: string) => new Failure(ErrorCodes.ISSUER_NOT_TRUSTED, detail);
  let entry: TrustEntry | null;
  try {
    entry = await o.trustRegistry.lookup(fingerprint, o.now);
  } catch (e) {
    if (e instanceof TrustListUnavailableError) throw new Failure(ErrorCodes.TRUST_LIST_UNAVAILABLE, 'no valid trust list');
    throw untrusted('trust registry failed');
  }
  if (!entry) throw untrusted('certificate is not in the trust list');
  if (entry.mucDich !== 'vc') throw untrusted('certificate purpose is not vc');
  if (entry.maToChuc !== leaf.subject.organizationIdentifier) throw untrusted('organizationIdentifier differs from the trust list entry');
  if (!Array.isArray(entry.vct) || !entry.vct.includes(p['vct'] as string)) throw untrusted('trust list entry does not cover this vct');
  if (p['vct'] === VCT.productEvent && !(typeof p['cong_doan'] === 'string' && Array.isArray(entry.congDoan) && entry.congDoan.includes(p['cong_doan']))) {
    throw untrusted('trust list entry does not cover this cong_doan');
  }
  return entry;
}

function statusRef(p: Record<string, unknown>): { idx: number; uri: string } | null {
  const list = isObject(p['status']) ? p['status']['status_list'] : undefined;
  if (!isObject(list) || !Number.isSafeInteger(list['idx']) || (list['idx'] as number) < 0 || typeof list['uri'] !== 'string') return null;
  return { idx: list['idx'] as number, uri: list['uri'] };
}

async function checkStatus(o: VerifyCredentialOptions, p: Record<string, unknown>, entry: TrustEntry): Promise<void> {
  const unavailable = (detail: string) => new Failure(ErrorCodes.STATUS_UNAVAILABLE, detail);
  const ref = statusRef(p);
  if (!ref) throw unavailable('status.status_list with idx and uri is missing or invalid');
  if (!ref.uri.startsWith('https://') || !ref.uri.startsWith(`${p['iss'] as string}/status/`)) throw unavailable('status uri is not under <iss>/status/');
  let answer: unknown;
  try {
    answer = await o.statusChecker.check(ref, { maToChuc: entry.maToChuc });
  } catch {
    throw unavailable('status checker failed');
  }
  if (answer === 'revoked') throw new Failure(ErrorCodes.REVOKED, 'credential is revoked');
  if (answer === 'suspended') throw new Failure(ErrorCodes.SUSPENDED, 'credential is suspended');
  if (answer !== 'valid') throw unavailable('status could not be established');
}

/** Verifies a stored credential, or a presentation when `options.presentation` is given. */
export async function verifyCredential(compact: unknown, options: VerifyCredentialOptions): Promise<CredentialVerificationResult> {
  checkOptions(options);
  const checks: Check[] = [];
  const pass = (id: CheckId) => void checks.push({ id, ok: true, code: null });
  const fail = (id: CheckId, f: Failure) => void checks.push({ id, ok: false, code: f.code, detail: f.detail });
  const skip = (ids: CheckId[]) => ids.forEach((id) => checks.push({ id, ok: false, code: ErrorCodes.SKIPPED, skipped: true }));
  const done = (extra: Partial<CredentialVerificationResult> = {}): CredentialVerificationResult => ({ ok: checks.every((c) => c.ok), checks, ...extra });

  // Steps 1-4 gate the rest: payload data is not trusted before the issuer signature verified.
  let parsed: ParsedSdJwt | undefined;
  let chainChecks: Check[] | undefined;
  let leaf: ParsedCertificate;
  let fingerprint: string;
  try {
    parsed = checkStructure(compact, options.presentation !== undefined);
    pass('structure');
    if (checkJwsAlgorithm(parsed.jws.header) !== null) throw new Failure(ErrorCodes.ALG_NOT_ALLOWED, 'alg is not ES256');
    pass('algorithm');
    const chain = await options.chainValidator.validate({
      x5c: parsed.jws.header['x5c'] as string[],
      profile: 'vc',
      now: options.now,
      expectedIssuerUri: parsed.payload['iss'] as string,
    });
    chainChecks = chain.checks.map(({ id, ok, code, skipped }) => ({ id, ok, code, ...(skipped ? { skipped } : {}) }));
    if (!chain.ok) throw new Failure(chain.code!, chain.checks.find((c) => !c.ok)?.detail ?? 'certificate chain is not valid');
    leaf = chain.leaf!;
    fingerprint = chain.fingerprint!;
    pass('certificate_chain');
    if (!(await verifyJwsSignature(parsed.jws, leaf.publicJwk!, options.verifier))) {
      throw new Failure(ErrorCodes.SIGNATURE_INVALID, 'issuer signature does not verify');
    }
    pass('signature');
  } catch (e) {
    if (!(e instanceof Failure)) throw e;
    const failed = checks.length;
    fail(GATED[failed]!, e);
    const holderListed = options.presentation !== undefined || (parsed?.disclosures.length ?? 0) > 0;
    skip([...GATED.slice(failed + 1), 'validity_time', 'credential_type', 'issuer_trust', 'status', ...(holderListed ? ['holder_binding' as const] : [])]);
    return done(chainChecks ? { chainChecks } : {});
  }

  // Steps 5-9 all run and all report.
  const p = parsed.payload;
  const run = async (id: CheckId, fn: () => unknown): Promise<boolean> => {
    try {
      await fn();
      pass(id);
      return true;
    } catch (e) {
      if (!(e instanceof Failure)) throw e;
      fail(id, e);
      return false;
    }
  };
  await run('validity_time', () => checkValidityTime(p, options.now));
  await run('credential_type', () => {
    if (!options.supportedVcts.includes(p['vct'] as string)) throw new Failure(ErrorCodes.VCT_UNSUPPORTED, 'vct is not supported');
  });
  let entry: TrustEntry | undefined;
  const trusted = await run('issuer_trust', async () => void (entry = await checkIssuerTrust(options, fingerprint, leaf, p)));
  // No status request is sent on behalf of an untrusted issuer.
  if (trusted) await run('status', () => checkStatus(options, p, entry!));
  else skip(['status']);
  let claims: Record<string, unknown> | undefined = Object.fromEntries(
    Object.entries(p).filter(([k]) => !METADATA_CLAIMS.includes(k) && k !== '_sd' && k !== '_sd_alg'),
  );
  if (options.presentation !== undefined || parsed.disclosures.length > 0) {
    const r = await checkHolderBinding(parsed, options);
    if (r.ok) {
      pass('holder_binding');
      claims = { ...claims, ...r.disclosed };
    } else {
      fail('holder_binding', new Failure(r.code, r.detail));
      claims = undefined;
    }
  }
  // Step 10 (product_chain, CHAIN_BROKEN) is added here in GĐ6b; it needs the previous event.

  const credential: VerifiedCredential = {
    vct: p['vct'] as string,
    iss: p['iss'] as string,
    fingerprint,
    issuer: entry ? { maToChuc: entry.maToChuc, ten: entry.ten } : null,
    iat: p['iat'] as number,
  };
  if (isTime(p['nbf'])) credential.nbf = p['nbf'];
  if (isTime(p['exp'])) credential.exp = p['exp'];
  const ref = statusRef(p);
  if (ref) credential.status = ref;
  const cnfJwk = normalizeEcPublicJwk(isObject(p['cnf']) ? p['cnf']['jwk'] : undefined);
  if (cnfJwk) credential.cnfJwk = cnfJwk;
  if (claims) credential.claims = claims;
  return done({ ...(chainChecks ? { chainChecks } : {}), credential });
}
