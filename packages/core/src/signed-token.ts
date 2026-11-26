// Verification steps shared by the status list token and the trust list token (docs/architecture.md
// section 7): size cap before parsing, strict JWS, exact `typ`, the alg allow-list, the signer key (the
// x5c chain with the given profile, or for a DID-signed status list the DID `kid`, ADR-0020 section 6),
// the signature with that key, and `iat` / `exp` / `ttl`. Never throws for bad input.
import { resolveDidVerificationKey, splitDidUrl } from './did-jwk.js';
import { utf8Decode } from './encoding.js';
import type { CertificateChainValidator, CertificateProfile, DidResolver, EcPublicJwk, Verifier } from './interfaces.js';
import { checkJwsAlgorithm, decodeJws, verifyJws, type DecodedJws } from './jws.js';
import { CLOCK_SKEW_MS } from './x509/chain.js';
import type { ParsedCertificate } from './x509/parse.js';

/** Why a status list or trust list token was refused; for logs and tests, never shown as a claim. */
export type TokenFailureReason =
  | 'too_large'
  | 'malformed'
  | 'typ'
  | 'alg'
  | 'chain'
  /** A DID-signed token: `kid` is not a DID URL, or no usable assertionMethod key could be resolved for it. */
  | 'key'
  | 'signature'
  | 'not_yet_valid'
  | 'expired'
  | 'claims'
  | 'not_trusted'
  | 'trust_list_unavailable';

export interface TokenFailure {
  ok: false;
  reason: TokenFailureReason;
  /** For logs only; never contains token content. */
  detail: string;
}

export interface VerifiedSignedToken {
  ok: true;
  payload: Record<string, unknown>;
  iat: number;
  exp: number;
  ttl?: number;
  leaf: ParsedCertificate;
  /** base64url SHA-256 of the signer certificate DER. */
  fingerprint: string;
}

const SKEW_S = CLOCK_SKEW_MS / 1000;
/**
 * ADR-0019 section 1: a status list or trust list token may live at most 24 hours (exp - iat,
 * plus the 60 s skew), whatever its signer wrote. With the freshness caps of token-cache.ts this
 * bounds how long a removal or a revocation can stay unseen by a client that fetched one list.
 */
export const MAX_TOKEN_LIFETIME_SECONDS = 86_400;
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
export const fail = (reason: TokenFailureReason, detail: string): TokenFailure => ({ ok: false, reason, detail });

/** The timed claims of a verified token, without the signer. */
type SignedClaims = Omit<VerifiedSignedToken, 'leaf' | 'fingerprint'>;

export interface VerifiedDidSignedToken extends SignedClaims {
  /** The DID URL of the signing key and that key. */
  kid: string;
  publicJwk: EcPublicJwk;
}

/** Size cap, strict JWS, `typ`, alg; a header with both `x5c` and a DID `kid` is malformed. */
function decodeTyped(token: unknown, typ: string, maxBytes: number): { ok: true; jws: DecodedJws } | TokenFailure {
  const decoded = decodeJws(token, maxBytes);
  if (!decoded.ok) return fail(decoded.code === 'TOO_LARGE' ? 'too_large' : 'malformed', decoded.detail);
  const { jws } = decoded;
  if (jws.header['typ'] !== typ) return fail('typ', `typ is not ${typ}`);
  if (checkJwsAlgorithm(jws.header) !== null) return fail('alg', 'alg is not ES256');
  if (jws.header['x5c'] !== undefined && typeof jws.header['kid'] === 'string' && jws.header['kid'].startsWith('did:')) {
    return fail('malformed', 'the header carries both x5c and a DID kid');
  }
  return { ok: true, jws };
}

/** The signature with `publicJwk`, then the payload and its `iat` / `exp` / `ttl`. */
async function checkSignedClaims(jws: DecodedJws, publicJwk: EcPublicJwk, verifier: Verifier, now: Date): Promise<SignedClaims | TokenFailure> {
  if ((await verifyJws(jws, publicJwk, verifier)) !== null) return fail('signature', 'signature does not verify');
  let payload: unknown;
  try {
    payload = JSON.parse(utf8Decode(jws.payload));
  } catch {
    return fail('malformed', 'payload is not JSON');
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return fail('malformed', 'payload is not a JSON object');
  const p = payload as Record<string, unknown>;
  const t = now.getTime() / 1000;
  // An integer: the iat is compared for equality and persisted in `seen`, which holds integers only.
  if (!isTime(p['iat']) || !Number.isSafeInteger(p['iat'])) return fail('claims', 'iat is missing or not an integer');
  if (!isTime(p['exp'])) return fail('claims', 'exp is missing or not a number');
  if (p['ttl'] !== undefined && !(Number.isSafeInteger(p['ttl']) && (p['ttl'] as number) > 0)) return fail('claims', 'ttl is not a positive integer');
  if (p['exp'] - p['iat'] > MAX_TOKEN_LIFETIME_SECONDS + SKEW_S) return fail('claims', 'exp - iat is more than 24 hours');
  if (p['iat'] > t + SKEW_S) return fail('not_yet_valid', 'iat is in the future');
  if (p['exp'] <= t - SKEW_S) return fail('expired', 'exp has passed');
  const result: SignedClaims = { ok: true, payload: p, iat: p['iat'], exp: p['exp'] };
  if (p['ttl'] !== undefined) result.ttl = p['ttl'] as number;
  return result;
}

export async function verifySignedToken(
  token: unknown,
  o: { typ: string; profile: CertificateProfile; maxBytes: number; chainValidator: CertificateChainValidator; verifier: Verifier; now: Date },
): Promise<VerifiedSignedToken | TokenFailure> {
  const decoded = decodeTyped(token, o.typ, o.maxBytes);
  if (!decoded.ok) return decoded;
  const chain = await o.chainValidator.validate({ x5c: decoded.jws.header['x5c'] as string[], profile: o.profile, now: o.now });
  if (!chain.ok) return fail('chain', `certificate chain: ${chain.code}`);
  const leaf = chain.leaf!;
  const r = await checkSignedClaims(decoded.jws, leaf.publicJwk!, o.verifier, o.now);
  return r.ok ? { ...r, leaf, fingerprint: chain.fingerprint! } : r;
}

/**
 * A token signed with the key of a DID (ADR-0020 section 6): no `x5c`, `kid` = `<did>#<fragment>`
 * with `<did>` exactly `did` (`not_trusted` otherwise), the key an `assertionMethod` EC P-256 key of
 * that DID as `didResolver` resolves it (`key` otherwise), then the rules of verifySignedToken.
 */
export async function verifyDidSignedToken(
  token: unknown,
  o: { typ: string; maxBytes: number; did: string; didResolver: DidResolver; verifier: Verifier; now: Date },
): Promise<VerifiedDidSignedToken | TokenFailure> {
  const decoded = decodeTyped(token, o.typ, o.maxBytes);
  if (!decoded.ok) return decoded;
  const { header } = decoded.jws;
  if (header['x5c'] !== undefined) return fail('malformed', 'a DID-signed token carries no x5c');
  const parts = splitDidUrl(header['kid']);
  if (!parts) return fail('key', 'kid is not a DID URL with a fragment');
  if (parts.did !== o.did) return fail('not_trusted', 'the token is signed by another DID');
  const key = await resolveDidVerificationKey(header['kid'], o.didResolver);
  if (!key.ok) return fail('key', `${key.code}: ${key.detail}`);
  const r = await checkSignedClaims(decoded.jws, key.publicJwk, o.verifier, o.now);
  return r.ok ? { ...r, kid: header['kid'] as string, publicJwk: key.publicJwk } : r;
}

/** Checks of the arguments of a token builder; programmer errors throw TypeError. */
export function tokenTimes(now: Date, ttlSeconds: number, lifetimeSeconds: number): { iat: number; exp: number; ttl: number } {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) throw new TypeError('ttlSeconds must be a positive integer');
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < ttlSeconds || lifetimeSeconds > MAX_TOKEN_LIFETIME_SECONDS) {
    throw new TypeError('lifetimeSeconds must be an integer from ttlSeconds to 86 400');
  }
  const iat = Math.floor(now.getTime() / 1000);
  return { iat, exp: iat + lifetimeSeconds, ttl: ttlSeconds };
}
