// Access tokens of the issuer: a JWS `typ: at+jwt` (RFC 9068 layout) signed by the in-memory
// access-token key, carrying `iss`, `aud` (both the issuer identifier), `iat`, `exp` and a random
// `jti`. The signature only proves the token is ours; single use and the binding to an offer live
// in the state store under the `jti`.
import { decodeJws, signJws, utf8Decode, utf8Encode, verifyJws, type EcPublicJwk, type Signer, type Verifier } from '@identra/sdk-core';

export const ACCESS_TOKEN_SECONDS = 300;
const MAX_TOKEN_BYTES = 2048;
const SKEW_SECONDS = 60;
const JTI = /^[A-Za-z0-9_-]{22}$/;

export function signAccessToken(o: { signer: Signer & { kid: string }; issuerUri: string; jti: string; now: Date }): Promise<string> {
  const iat = Math.floor(o.now.getTime() / 1000);
  const payload = { iss: o.issuerUri, aud: o.issuerUri, iat, exp: iat + ACCESS_TOKEN_SECONDS, jti: o.jti };
  return signJws({ typ: 'at+jwt', kid: o.signer.kid }, utf8Encode(JSON.stringify(payload)), o.signer);
}

/** The `jti` of a valid, unexpired access token of this issuer sent as `Bearer`; null for anything else. Never throws. */
export async function verifyAccessToken(
  authorization: string | undefined,
  o: { publicJwk: EcPublicJwk & { kid: string }; verifier: Verifier; issuerUri: string; now: Date },
): Promise<string | null> {
  const m = /^Bearer ([A-Za-z0-9._-]+)$/i.exec(authorization ?? '');
  if (!m) return null;
  const decoded = decodeJws(m[1], MAX_TOKEN_BYTES);
  if (!decoded.ok) return null;
  const { header } = decoded.jws;
  if (header['typ'] !== 'at+jwt' || header['kid'] !== o.publicJwk.kid) return null;
  if ((await verifyJws(decoded.jws, o.publicJwk, o.verifier)) !== null) return null;
  let p: Record<string, unknown>;
  try {
    p = JSON.parse(utf8Decode(decoded.jws.payload)) as Record<string, unknown>;
  } catch {
    return null;
  }
  const now = o.now.getTime() / 1000;
  if (typeof p !== 'object' || p === null || p['iss'] !== o.issuerUri || p['aud'] !== o.issuerUri) return null;
  if (typeof p['exp'] !== 'number' || p['exp'] <= now || typeof p['iat'] !== 'number' || p['iat'] > now + SKEW_SECONDS) return null;
  return typeof p['jti'] === 'string' && JTI.test(p['jti']) ? p['jti'] : null;
}
