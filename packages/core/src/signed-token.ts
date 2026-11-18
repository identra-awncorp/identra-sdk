// Verification steps shared by the status list token and the trust list token (docs/architecture.md
// section 7): size cap before parsing, strict JWS, exact `typ`, the alg allow-list, the x5c chain
// with the given profile, the signature with the leaf key, and `iat` / `exp` / `ttl`.
// Never throws for bad input.
import { utf8Decode } from './encoding.js';
import type { CertificateChainValidator, CertificateProfile, Verifier } from './interfaces.js';
import { checkJwsAlgorithm, decodeJws, verifyJws } from './jws.js';
import { CLOCK_SKEW_MS } from './x509/chain.js';
import type { ParsedCertificate } from './x509/parse.js';

/** Why a status list or trust list token was refused; for logs and tests, never shown as a claim. */
export type TokenFailureReason =
  | 'too_large'
  | 'malformed'
  | 'typ'
  | 'alg'
  | 'chain'
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
const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
export const fail = (reason: TokenFailureReason, detail: string): TokenFailure => ({ ok: false, reason, detail });

export async function verifySignedToken(
  token: unknown,
  o: { typ: string; profile: CertificateProfile; maxBytes: number; chainValidator: CertificateChainValidator; verifier: Verifier; now: Date },
): Promise<VerifiedSignedToken | TokenFailure> {
  const decoded = decodeJws(token, o.maxBytes);
  if (!decoded.ok) return fail(decoded.code === 'TOO_LARGE' ? 'too_large' : 'malformed', decoded.detail);
  const { jws } = decoded;
  if (jws.header['typ'] !== o.typ) return fail('typ', `typ is not ${o.typ}`);
  if (checkJwsAlgorithm(jws.header) !== null) return fail('alg', 'alg is not ES256');
  const chain = await o.chainValidator.validate({ x5c: jws.header['x5c'] as string[], profile: o.profile, now: o.now });
  if (!chain.ok) return fail('chain', `certificate chain: ${chain.code}`);
  const leaf = chain.leaf!;
  if ((await verifyJws(jws, leaf.publicJwk!, o.verifier)) !== null) return fail('signature', 'signature does not verify');
  let payload: unknown;
  try {
    payload = JSON.parse(utf8Decode(jws.payload));
  } catch {
    return fail('malformed', 'payload is not JSON');
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return fail('malformed', 'payload is not a JSON object');
  const p = payload as Record<string, unknown>;
  const t = o.now.getTime() / 1000;
  if (!isTime(p['iat'])) return fail('claims', 'iat is missing or not a number');
  if (!isTime(p['exp'])) return fail('claims', 'exp is missing or not a number');
  if (p['ttl'] !== undefined && !(Number.isSafeInteger(p['ttl']) && (p['ttl'] as number) > 0)) return fail('claims', 'ttl is not a positive integer');
  if (p['iat'] > t + SKEW_S) return fail('not_yet_valid', 'iat is in the future');
  if (p['exp'] <= t - SKEW_S) return fail('expired', 'exp has passed');
  const result: VerifiedSignedToken = { ok: true, payload: p, iat: p['iat'], exp: p['exp'], leaf, fingerprint: chain.fingerprint! };
  if (p['ttl'] !== undefined) result.ttl = p['ttl'] as number;
  return result;
}

/** Checks of the arguments of a token builder; programmer errors throw TypeError. */
export function tokenTimes(now: Date, ttlSeconds: number, lifetimeSeconds: number): { iat: number; exp: number; ttl: number } {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('now must be a valid Date');
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) throw new TypeError('ttlSeconds must be a positive integer');
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < ttlSeconds) throw new TypeError('lifetimeSeconds must be an integer of at least ttlSeconds');
  const iat = Math.floor(now.getTime() / 1000);
  return { iat, exp: iat + lifetimeSeconds, ttl: ttlSeconds };
}
