// The verification policy (docs/architecture.md section 3, ADR-0007, ADR-0015 section 7) with its two
// trust paths, X.509 and DID (ADR-0020). Never throws for bad input; throws TypeError only for
// missing or wrong options.
import { isCertNetDid } from '../did-certnet.js';
import { resolveDidVerificationKey, splitDidUrl } from '../did-jwk.js';
import type {
  CertificateChainValidator, DidResolver, DidTrustRegistry, EcPublicJwk, Hasher, StatusChecker, TrustEntry, TrustRegistry, Verifier,
} from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { checkJwsAlgorithm, verifyJws } from '../jws.js';
import { ErrorCodes, TrustListUnavailableError, type Check, type CheckId, type ErrorCode, type VerificationResult } from '../results.js';
import type { ParsedCertificate } from '../x509/parse.js';
import { disclosureSegments, jsonDepthExceeds, MAX_JSON_DEPTH, parseSdJwt, sdShapeProblem, type ParsedSdJwt } from './compact.js';
import { isDidStatusListUri, isStatusListUri, METADATA_CLAIMS, SD_JWT_LIMITS, VCT } from './credential-types.js';
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
  /**
   * The DID trust path (ADR-0020 sections 3-5): without it a credential whose header `kid` is a DID
   * fails `did_resolution` with DID_RESOLUTION_FAILED. Both members are required together.
   */
  dpki?: { resolver: DidResolver; trustRegistry: DidTrustRegistry };
}

export interface VerifyPresentationOptions extends VerifyCredentialOptions {
  /** The KB-JWT must carry this nonce and audience. */
  presentation: { nonce: string; audience: string };
}

interface VerifiedCredentialFields {
  vct: string;
  iss: string;
  iat: number;
  nbf?: number;
  exp?: number;
  status?: { idx: number; uri: string };
  cnfJwk?: EcPublicJwk;
  /** Subject claims (visible plus verified disclosures); only when the whole result is ok. */
  claims?: Record<string, unknown>;
}

export type VerifiedCredential = VerifiedCredentialFields &
  (
    | {
        trustPath: 'x509';
        /** base64url SHA-256 of the issuer leaf certificate. */
        fingerprint: string;
        /** From the trust list; null unless the issuer_trust check passed. */
        issuer: { maToChuc: string; ten: string } | null;
      }
    | {
        trustPath: 'did';
        /** The issuer's DID (= `iss`). */
        issuerDid: string;
        /** No display name on the DID path (ADR-0020 section 1). */
        issuer: null;
      }
  );

export interface CredentialVerificationResult extends VerificationResult {
  /** The steps of certificate chain validation, without detail strings (X.509 path only). */
  chainChecks?: Check[];
  /** Only when the checks structure, algorithm, certificate_chain (or did_resolution) and signature passed. */
  credential?: VerifiedCredential;
}

class Failure {
  constructor(
    readonly code: ErrorCode,
    readonly detail: string,
  ) {}
}
const GATED: CheckId[] = ['structure', 'algorithm', 'certificate_chain', 'signature'];
const GATED_DID: CheckId[] = ['structure', 'algorithm', 'did_resolution', 'signature'];
const isDidKid = (kid: unknown): boolean => typeof kid === 'string' && kid.startsWith('did:');
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

function checkOptions(o: VerifyCredentialOptions, presentation: { nonce: string; audience: string } | undefined): void {
  const fns: [unknown, string][] = [
    [o?.verifier?.verify, 'verifier'],
    [o?.hasher?.sha256, 'hasher'],
    [o?.chainValidator?.validate, 'chainValidator'],
    [o?.trustRegistry?.lookup, 'trustRegistry'],
    [o?.statusChecker?.check, 'statusChecker'],
  ];
  for (const [fn, name] of fns) if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  if (o.dpki !== undefined && (typeof o.dpki?.resolver?.resolve !== 'function' || typeof o.dpki.trustRegistry?.lookupIssuer !== 'function')) {
    throw new TypeError('dpki needs a resolver and a trustRegistry');
  }
  if (!Array.isArray(o.supportedVcts)) throw new TypeError('supportedVcts must be an array');
  if (!(o.now instanceof Date) || Number.isNaN(o.now.getTime())) throw new TypeError('now must be a valid Date');
  const p = presentation;
  if (p !== undefined && (typeof p?.nonce !== 'string' || p.nonce === '' || typeof p.audience !== 'string' || p.audience === '')) {
    throw new TypeError('presentation needs a non-empty nonce and audience');
  }
}

// Step 1: compact form, typ, sizes, and the shape (not the truth) of the metadata claims.
function checkStructure(compact: unknown, presentation: boolean): ParsedSdJwt {
  const parsed = parseSdJwt(compact);
  if (!parsed.ok) throw new Failure(parsed.code, parsed.detail);
  const { jws, payload, kbJwt } = parsed.sdJwt;
  if (jws.header['typ'] !== 'dc+sd-jwt') throw new Failure(ErrorCodes.TYP_INVALID, 'typ is not dc+sd-jwt');
  // ADR-0020 section 2: one trust path per credential.
  if (jws.header['x5c'] !== undefined && isDidKid(jws.header['kid'])) throw new Failure(ErrorCodes.MALFORMED, 'the header carries both x5c and a DID kid');
  if (kbJwt !== null && !presentation) throw new Failure(ErrorCodes.MALFORMED, 'a stored credential carries no KB-JWT');
  const p = payload;
  const shapeOk =
    typeof p['iss'] === 'string' && typeof p['vct'] === 'string' && isTime(p['iat']) &&
    (p['nbf'] === undefined || isTime(p['nbf'])) && (p['exp'] === undefined || isTime(p['exp'])) &&
    (p['cnf'] === undefined || isObject(p['cnf'])) && (p['status'] === undefined || isObject(p['status']));
  if (!shapeOk) throw new Failure(ErrorCodes.MALFORMED, 'payload lacks string iss / vct, numeric iat, or has mistyped metadata');
  const sdProblem = sdShapeProblem(p);
  if (sdProblem) throw new Failure(ErrorCodes.MALFORMED, sdProblem);
  if (jsonDepthExceeds(p, MAX_JSON_DEPTH)) throw new Failure(ErrorCodes.MALFORMED, `payload nests deeper than ${MAX_JSON_DEPTH} levels`);
  return parsed.sdJwt;
}

function checkValidityTime(p: Record<string, unknown>, now: Date): void {
  const t = now.getTime() / 1000;
  const skew = SD_JWT_LIMITS.clockSkewSeconds;
  if ((p['iat'] as number) > t + skew) throw new Failure(ErrorCodes.NOT_YET_VALID, 'iat is in the future');
  if (isTime(p['nbf']) && p['nbf'] > t + skew) throw new Failure(ErrorCodes.NOT_YET_VALID, 'nbf is in the future');
  if (isTime(p['exp']) && p['exp'] <= t - skew) throw new Failure(ErrorCodes.EXPIRED, 'exp has passed');
}

/**
 * Step 3 on the DID path (ADR-0020 section 4), in this order: the path is configured, `kid` is
 * `<did>#<fragment>`, `iss` is that DID, the DID is did:certnet (all without a network call), then
 * resolution and the assertionMethod EC P-256 key.
 */
async function resolveIssuerKey(o: VerifyCredentialOptions, kid: unknown, iss: string): Promise<{ did: string; publicJwk: EcPublicJwk }> {
  if (!o.dpki) throw new Failure(ErrorCodes.DID_RESOLUTION_FAILED, 'the DID trust path is not configured');
  const parts = splitDidUrl(kid);
  if (!parts) throw new Failure(ErrorCodes.KEY_NOT_FOUND, 'kid is not <did>#<fragment>');
  if (iss !== parts.did) throw new Failure(ErrorCodes.ISSUER_MISMATCH, 'iss is not the DID of kid');
  if (!isCertNetDid(parts.did)) throw new Failure(ErrorCodes.DID_RESOLUTION_FAILED, 'not a did:certnet DID');
  const key = await resolveDidVerificationKey(kid, o.dpki.resolver);
  if (!key.ok) throw new Failure(key.code, key.detail);
  return { did: parts.did, publicJwk: key.publicJwk };
}

/** Step 7 on the DID path (ADR-0020 section 5); no display name exists on this path. */
async function checkDidIssuerTrust(o: VerifyCredentialOptions, did: string, p: Record<string, unknown>): Promise<void> {
  const untrusted = (detail: string) => new Failure(ErrorCodes.ISSUER_NOT_TRUSTED, detail);
  if (p['vct'] === VCT.productEvent) throw untrusted('product events have no DID trust path');
  let answer: Awaited<ReturnType<DidTrustRegistry['lookupIssuer']>>;
  try {
    answer = await o.dpki!.trustRegistry.lookupIssuer(did, p['vct'] as string, o.now);
  } catch (e) {
    if (e instanceof TrustListUnavailableError) throw new Failure(ErrorCodes.TRUST_LIST_UNAVAILABLE, 'no usable answer from the DID trust registry');
    throw untrusted('DID trust registry failed');
  }
  if (answer?.trusted !== true) throw untrusted(`not trusted by the DID trust registry: ${String((answer as { detail?: unknown } | null)?.detail)}`);
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

/** `issuer`: the organisation of an X.509 issuer, or the DID of a DID issuer. */
async function checkStatus(o: VerifyCredentialOptions, p: Record<string, unknown>, issuer: { maToChuc: string } | { did: string }): Promise<void> {
  const unavailable = (detail: string) => new Failure(ErrorCodes.STATUS_UNAVAILABLE, detail);
  const ref = statusRef(p);
  if (!ref) throw unavailable('status.status_list with idx and uri is missing or invalid');
  if ('did' in issuer) {
    if (!isDidStatusListUri(ref.uri)) throw unavailable('status uri is not https://<host>/<path>/status/<n>');
  } else if (!isStatusListUri(ref.uri, p['iss'] as string)) throw unavailable('status uri is not <iss>/status/<n>');
  let answer: unknown;
  try {
    answer = await o.statusChecker.check(ref, issuer);
  } catch {
    throw unavailable('status checker failed');
  }
  if (answer === 'revoked') throw new Failure(ErrorCodes.REVOKED, 'credential is revoked');
  if (answer === 'suspended') throw new Failure(ErrorCodes.SUSPENDED, 'credential is suspended');
  if (answer !== 'valid') throw unavailable('status could not be established');
}

/**
 * Verifies a credential PRESENTED BY ANOTHER PARTY: steps 1-9, including the KB-JWT that proves
 * possession of `cnf.jwk` for `options.presentation` (nonce, audience). Use this for anything
 * received from a holder.
 */
export async function verifyPresentation(compact: unknown, options: VerifyPresentationOptions): Promise<CredentialVerificationResult> {
  if (options?.presentation === undefined) throw new TypeError('verifyPresentation needs options.presentation');
  return verify(compact, options, options.presentation);
}

/**
 * MUST NOT be used to accept a credential presented by someone else: it never proves possession.
 * Verifies a credential the caller already holds (a wallet on receipt or display, a public
 * product event): steps 1-8 and the disclosures; a compact carrying a KB-JWT is MALFORMED.
 */
export async function verifyStoredCredential(compact: unknown, options: VerifyCredentialOptions): Promise<CredentialVerificationResult> {
  if ((options as { presentation?: unknown })?.presentation !== undefined) throw new TypeError('use verifyPresentation for a presentation');
  return verify(compact, options, undefined);
}

async function verify(
  compact: unknown,
  options: VerifyCredentialOptions,
  presentation: { nonce: string; audience: string } | undefined,
): Promise<CredentialVerificationResult> {
  checkOptions(options, presentation);
  const checks: Check[] = [];
  const pass = (id: CheckId) => void checks.push({ id, ok: true, code: null });
  const fail = (id: CheckId, f: Failure) => void checks.push({ id, ok: false, code: f.code, detail: f.detail });
  const skip = (ids: CheckId[]) => ids.forEach((id) => checks.push({ id, ok: false, code: ErrorCodes.SKIPPED, skipped: true }));
  const done = (extra: Partial<CredentialVerificationResult> = {}): CredentialVerificationResult => ({ ok: checks.every((c) => c.ok), checks, ...extra });

  // Steps 1-4 gate the rest: payload data is not trusted before the issuer signature verified.
  let parsed: ParsedSdJwt | undefined;
  let chainChecks: Check[] | undefined;
  let gated = GATED;
  // The X.509 path sets leaf and fingerprint, the DID path issuerDid.
  let leaf: ParsedCertificate | undefined;
  let fingerprint: string | undefined;
  let issuerDid: string | undefined;
  try {
    parsed = checkStructure(compact, presentation !== undefined);
    // ADR-0020 section 2: no x5c and a DID kid is the DID path; everything else the X.509 path as before.
    // Known once the header is read, so a failure from step 2 on names the step 3 of this path.
    const didPath = parsed.jws.header['x5c'] === undefined && isDidKid(parsed.jws.header['kid']);
    if (didPath) gated = GATED_DID;
    pass('structure');
    if (checkJwsAlgorithm(parsed.jws.header) !== null) throw new Failure(ErrorCodes.ALG_NOT_ALLOWED, 'alg is not ES256');
    pass('algorithm');
    let issuerKey: EcPublicJwk;
    if (didPath) {
      const key = await resolveIssuerKey(options, parsed.jws.header['kid'], parsed.payload['iss'] as string);
      issuerDid = key.did;
      issuerKey = key.publicJwk;
      pass('did_resolution');
    } else {
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
      issuerKey = leaf.publicJwk!;
      pass('certificate_chain');
    }
    const signature = await verifyJws(parsed.jws, issuerKey, options.verifier);
    if (signature !== null) throw new Failure(signature, 'issuer signature does not verify');
    pass('signature');
  } catch (e) {
    if (!(e instanceof Failure)) throw e;
    const failed = checks.length;
    fail(gated[failed]!, e);
    // Decided from what is knowable without parsing, so every step 1-4 failure lists the same checks.
    const holderListed = presentation !== undefined || disclosureSegments(compact) > 0;
    skip([...gated.slice(failed + 1), 'validity_time', 'credential_type', 'issuer_trust', 'status', ...(holderListed ? ['holder_binding' as const] : [])]);
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
  const typeOk = await run('credential_type', () => {
    if (!options.supportedVcts.includes(p['vct'] as string)) throw new Failure(ErrorCodes.VCT_UNSUPPORTED, 'vct is not supported');
  });
  let entry: TrustEntry | undefined;
  const trusted = await run('issuer_trust', async () => {
    if (issuerDid !== undefined) await checkDidIssuerTrust(options, issuerDid, p);
    else entry = await checkIssuerTrust(options, fingerprint!, leaf!, p);
  });
  // No status request on behalf of an untrusted issuer, nor for a credential of an unsupported type.
  if (trusted && typeOk) await run('status', () => checkStatus(options, p, issuerDid !== undefined ? { did: issuerDid } : { maToChuc: entry!.maToChuc }));
  else skip(['status']);
  let claims: Record<string, unknown> | undefined = Object.fromEntries(
    Object.entries(p).filter(([k]) => !METADATA_CLAIMS.includes(k) && k !== '_sd' && k !== '_sd_alg'),
  );
  if (presentation !== undefined || disclosureSegments(compact) > 0) {
    const r = await checkHolderBinding(parsed, { ...options, ...(presentation ? { presentation } : {}) });
    if (r.ok) {
      pass('holder_binding');
      claims = { ...claims, ...r.disclosed };
    } else {
      fail('holder_binding', new Failure(r.code, r.detail));
      claims = undefined;
    }
  }
  // Step 10 (product_chain, CHAIN_BROKEN) is added here in GĐ6b; it needs the previous event.

  const fields = { vct: p['vct'] as string, iss: p['iss'] as string, iat: p['iat'] as number };
  const credential: VerifiedCredential = issuerDid !== undefined
    ? { trustPath: 'did', ...fields, issuerDid, issuer: null }
    : { trustPath: 'x509', ...fields, fingerprint: fingerprint!, issuer: entry ? { maToChuc: entry.maToChuc, ten: entry.ten } : null };
  if (isTime(p['nbf'])) credential.nbf = p['nbf'];
  if (isTime(p['exp'])) credential.exp = p['exp'];
  const ref = statusRef(p);
  if (ref) credential.status = ref;
  const cnfJwk = normalizeEcPublicJwk(isObject(p['cnf']) ? p['cnf']['jwk'] : undefined);
  if (cnfJwk) credential.cnfJwk = cnfJwk;
  // Claim values are handed out only for a credential that passed every check.
  if (claims && checks.every((c) => c.ok)) credential.claims = claims;
  return done({ ...(chainChecks ? { chainChecks } : {}), credential });
}
