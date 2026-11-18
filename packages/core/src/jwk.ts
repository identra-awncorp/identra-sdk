// EC P-256 public JWK helpers. Only P-256 exists (ADR-0015 section 3); private keys never
// pass through the SDK API as JWK (ADR-0006 section 3).
import { base64UrlDecode, base64UrlEncode, utf8Encode } from './encoding.js';
import type { EcPublicJwk, Hasher } from './interfaces.js';

// Private members of every JWK key type (RFC 7518 section 6).
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

// P-256 (SEC 2 / FIPS 186-4): y^2 = x^3 - 3x + b over GF(p).
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function toBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** True when (x, y), 32-byte big-endian coordinates, is a point on P-256 (the point at infinity has no such encoding). */
export function isP256Point(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== 32 || y.length !== 32) return false;
  const X = toBigInt(x);
  const Y = toBigInt(y);
  if (X >= P || Y >= P || (X === 0n && Y === 0n)) return false;
  const rhs = (((X * X) % P) * X - 3n * X + B) % P;
  return (Y * Y) % P === (rhs + P) % P;
}

function coordinate(v: unknown): Uint8Array | null {
  if (typeof v !== 'string') return null;
  try {
    const bytes = base64UrlDecode(v);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Returns `{ kty, crv, x, y }` for a valid EC P-256 public JWK, dropping every other member,
 * or null when the input is not exactly that: other curve or key type, private members,
 * coordinates that are not strict base64url of 32 bytes, or a point that is not on the curve.
 * Never throws.
 */
export function normalizeEcPublicJwk(jwk: unknown): EcPublicJwk | null {
  try {
    if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) return null;
    const j = jwk as Record<string, unknown>;
    if (PRIVATE_MEMBERS.some((m) => m in j)) return null;
    if (j['kty'] !== 'EC' || j['crv'] !== 'P-256') return null;
    const xs = j['x'];
    const ys = j['y'];
    const x = coordinate(xs);
    const y = coordinate(ys);
    if (!x || !y || !isP256Point(x, y)) return null;
    return { kty: 'EC', crv: 'P-256', x: xs as string, y: ys as string };
  } catch {
    return null;
  }
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) of an EC public key. */
export async function jwkThumbprint(jwk: EcPublicJwk, hasher: Hasher): Promise<string> {
  const n = normalizeEcPublicJwk(jwk);
  if (!n) throw new TypeError('not an EC P-256 public JWK');
  // Required members only, lexicographic order, no whitespace (RFC 7638 section 3.2).
  const canonical = `{"crv":"P-256","kty":"EC","x":"${n.x}","y":"${n.y}"}`;
  return base64UrlEncode(await hasher.sha256(utf8Encode(canonical)));
}
