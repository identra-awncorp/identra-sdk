// The signed trust list (ADR-0013 sections 6-8, ADR-0015 section 6): JWS typ identra-trust-list+jwt
// whose x5c is exactly one CA:FALSE certificate signed directly by a pinned root (profile
// `trust-list` of the chain validator), so a certificate of the Issuing CA can never sign it.
import { utf8Encode } from '../encoding.js';
import type { CertificateChainValidator, Signer, Verifier } from '../interfaces.js';
import { signJws } from '../jws.js';
import { fail, tokenTimes, verifySignedToken, type TokenFailure } from '../signed-token.js';
import { validateTrustListContent, validateTrustListPayload, type TrustListContent, type TrustListPayload } from './payload.js';

export const TRUST_LIST_TOKEN_TYP = 'identra-trust-list+jwt';
export const TRUST_LIST_TOKEN_MAX_BYTES = 256 * 1024;

export interface VerifiedTrustListToken {
  ok: true;
  payload: TrustListPayload;
  /** base64url SHA-256 of the trust-list signer certificate. */
  signerFingerprint: string;
}

export async function createTrustListToken(options: TrustListContent & {
  signer: Signer;
  now: Date;
  ttlSeconds?: number;
  lifetimeSeconds?: number;
}): Promise<string> {
  const { issuers, verifiers, signer, now, ttlSeconds = 3600, lifetimeSeconds = 86_400 } = options;
  if (!Array.isArray(signer?.x5c) || signer.x5c.length !== 1) throw new TypeError('the trust-list signer needs x5c of exactly its own certificate');
  const content = validateTrustListContent({ issuers, verifiers });
  if (!content.ok) throw new TypeError(`invalid trust list: ${content.detail}`);
  const { iat, exp, ttl } = tokenTimes(now, ttlSeconds, lifetimeSeconds);
  const payload: TrustListPayload = { iat, exp, ttl, issuers, verifiers };
  return signJws({ typ: TRUST_LIST_TOKEN_TYP }, utf8Encode(JSON.stringify(payload)), signer);
}

/** Never throws for bad input. */
export async function verifyTrustListToken(
  token: unknown,
  o: { chainValidator: CertificateChainValidator; verifier: Verifier; now: Date },
): Promise<VerifiedTrustListToken | TokenFailure> {
  const { chainValidator, verifier, now } = o;
  const r = await verifySignedToken(token, { typ: TRUST_LIST_TOKEN_TYP, profile: 'trust-list', maxBytes: TRUST_LIST_TOKEN_MAX_BYTES, chainValidator, verifier, now });
  if (!r.ok) return r;
  const payload = validateTrustListPayload(r.payload);
  if (!payload.ok) return fail('claims', payload.detail);
  return { ok: true, payload: payload.value, signerFingerprint: r.fingerprint };
}
