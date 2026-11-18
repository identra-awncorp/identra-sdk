// EC P-256 public JWK helpers. Only P-256 exists (ADR-0015 section 3); private keys never
// pass through the SDK API as JWK (ADR-0006 section 3).
import { base64UrlDecode, base64UrlEncode, utf8Encode } from './encoding.js';
import type { EcPublicJwk, Hasher } from './interfaces.js';

// Private members of every JWK key type (RFC 7518 section 6).
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

function isCoordinate(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  try {
    return base64UrlDecode(v).length === 32;
  } catch {
    return false;
  }
}

/**
 * Returns `{ kty, crv, x, y }` for a valid EC P-256 public JWK, dropping every other member,
 * or null when the input is not exactly that (other curve or key type, private members,
 * coordinates that are not strict base64url of 32 bytes). Whether the point lies on the curve
 * is left to the Verifier, which rejects such keys.
 */
export function normalizeEcPublicJwk(jwk: unknown): EcPublicJwk | null {
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) return null;
  const j = jwk as Record<string, unknown>;
  if (PRIVATE_MEMBERS.some((m) => m in j)) return null;
  if (j['kty'] !== 'EC' || j['crv'] !== 'P-256') return null;
  if (!isCoordinate(j['x']) || !isCoordinate(j['y'])) return null;
  return { kty: 'EC', crv: 'P-256', x: j['x'], y: j['y'] };
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) of an EC public key. */
export async function jwkThumbprint(jwk: EcPublicJwk, hasher: Hasher): Promise<string> {
  const n = normalizeEcPublicJwk(jwk);
  if (!n) throw new TypeError('not an EC P-256 public JWK');
  // Required members only, lexicographic order, no whitespace (RFC 7638 section 3.2).
  const canonical = `{"crv":"P-256","kty":"EC","x":"${n.x}","y":"${n.y}"}`;
  return base64UrlEncode(await hasher.sha256(utf8Encode(canonical)));
}
