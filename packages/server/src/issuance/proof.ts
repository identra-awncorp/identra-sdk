// The proof of possession of a credential request (OpenID4VCI 1.0 section 8.2.1.1, ADR-0010 point 4),
// checked by our own code on the core JWS primitives. The c_nonce it names is consumed by the caller.
import { checkJwsAlgorithm, decodeJws, normalizeEcPublicJwk, utf8Decode, verifyJws, type EcPublicJwk, type Verifier } from '@identra/sdk-core';

export const PROOF_TYP = 'openid4vci-proof+jwt';
/** `iat` may be at most this old (the c_nonce lifetime), with 60 s of clock skew either way. */
const MAX_AGE_SECONDS = 300;
const SKEW_SECONDS = 60;
const MAX_PROOF_BYTES = 4096;
/** Header members naming the key another way; the proof must carry exactly `jwk`. */
const OTHER_KEY_MEMBERS = ['kid', 'x5c', 'x5u', 'jku', 'trust_chain', 'key_attestation'];

export type ProofResult = { ok: true; jwk: EcPublicJwk; nonce: string } | { ok: false; error: 'invalid_proof' };

/**
 * All of: compact JWS of at most 4 KB; `typ` openid4vci-proof+jwt; `alg` ES256; header `jwk` a
 * valid on-curve P-256 public key with no private member and no other key reference; signature by
 * that key; `aud` = issuer identifier; numeric `iat` within [now - 360 s, now + 60 s]; a non-empty
 * string `nonce`. Never throws.
 */
export async function verifyProof(jwt: unknown, o: { issuerUri: string; verifier: Verifier; now: Date }): Promise<ProofResult> {
  const fail: ProofResult = { ok: false, error: 'invalid_proof' };
  const decoded = decodeJws(jwt, MAX_PROOF_BYTES);
  if (!decoded.ok) return fail;
  const { header } = decoded.jws;
  if (header['typ'] !== PROOF_TYP || checkJwsAlgorithm(header) !== null) return fail;
  if (OTHER_KEY_MEMBERS.some((m) => m in header)) return fail;
  const jwk = normalizeEcPublicJwk(header['jwk']);
  if (!jwk) return fail;
  if ((await verifyJws(decoded.jws, jwk, o.verifier)) !== null) return fail;
  let p: unknown;
  try {
    p = JSON.parse(utf8Decode(decoded.jws.payload));
  } catch {
    return fail;
  }
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return fail;
  const { aud, iat, nonce } = p as Record<string, unknown>;
  const now = o.now.getTime() / 1000;
  if (aud !== o.issuerUri) return fail;
  if (typeof iat !== 'number' || !(iat >= now - MAX_AGE_SECONDS - SKEW_SECONDS && iat <= now + SKEW_SECONDS)) return fail;
  if (typeof nonce !== 'string' || nonce === '') return fail;
  return { ok: true, jwk, nonce };
}
