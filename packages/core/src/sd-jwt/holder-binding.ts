// Step 9 of the verification policy: disclosures (ADR-0008 section 6) and the KB-JWT (section 4).
// Our own code on purpose (ADR-0004, "Bổ sung 2026-11-19" point 3): the library's verify checks
// the KB-JWT nonce before its signature (a nonce oracle for unsigned input), lets `iat` through as
// a disclosure, reports no per-rule code, and fetches the status list by default. Agreement with
// the library is tested by sd-jwt-differential.test.ts.
import { base64UrlEncode, utf8Decode, utf8Encode } from '../encoding.js';
import type { Hasher, Verifier } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { decodeJws, verifyJws } from '../jws.js';
import { ErrorCodes, type ErrorCode } from '../results.js';
import { containsReservedKey, type ParsedSdJwt } from './compact.js';
import { METADATA_CLAIMS, RESERVED_CLAIM_NAMES, SD_JWT_LIMITS } from './credential-types.js';

export type HolderBindingResult =
  | { ok: true; disclosed: Record<string, unknown> }
  | { ok: false; code: ErrorCode; detail: string };

const failure = (code: ErrorCode, detail: string): HolderBindingResult => ({ ok: false, code, detail });

/** Digest of a disclosure: base64url(SHA-256(ASCII of the disclosure exactly as received)). */
export async function disclosureDigest(encoded: string, hasher: Hasher): Promise<string> {
  return base64UrlEncode(await hasher.sha256(utf8Encode(encoded)));
}

/** KB-JWT `sd_hash`: base64url(SHA-256(`<issuer-jwt>~<disclosure>~...~`)). */
export async function sdHashOf(withoutKb: string, hasher: Hasher): Promise<string> {
  return base64UrlEncode(await hasher.sha256(utf8Encode(withoutKb)));
}

async function checkDisclosures(sdJwt: ParsedSdJwt, hasher: Hasher): Promise<HolderBindingResult> {
  const invalid = (detail: string) => failure(ErrorCodes.DISCLOSURE_INVALID, detail);
  // The payload's own SD shape (digest list, _sd_alg, nothing nested) is checked in step 1.
  const { payload, disclosures } = sdJwt;
  const sd = payload['_sd'];
  if (disclosures.length > 0 && !Array.isArray(sd)) return invalid('payload has no _sd digest list');
  const digests = new Set<string>();
  // No prototype: a disclosure named __proto__ stays a plain data property.
  const disclosed: Record<string, unknown> = Object.create(null);
  for (const d of disclosures) {
    if (d.array.length !== 3) return invalid('array-element disclosures are not supported');
    const [salt, name, value] = d.array;
    if (typeof salt !== 'string' || typeof name !== 'string') return invalid('disclosure salt and name must be strings');
    if (RESERVED_CLAIM_NAMES.includes(name)) return invalid('disclosure uses a reserved name');
    if (METADATA_CLAIMS.includes(name)) return invalid('metadata claim delivered by a disclosure');
    const digest = await disclosureDigest(d.encoded, hasher);
    if (digests.has(digest)) return invalid('duplicate disclosure');
    digests.add(digest);
    if (!(sd as string[]).includes(digest)) return invalid('disclosure is not referenced by _sd');
    if (Object.keys(disclosed).includes(name)) return invalid('two disclosures for one claim name');
    if (Object.keys(payload).includes(name)) return invalid('disclosure clashes with a payload claim');
    disclosed[name] = value;
  }
  if (containsReservedKey(Object.values(disclosed))) return invalid('nested or array-element selective disclosure is not supported');
  return { ok: true, disclosed };
}

async function checkKeyBinding(
  sdJwt: ParsedSdJwt,
  presentation: { nonce: string; audience: string },
  verifier: Verifier,
  hasher: Hasher,
  now: Date,
): Promise<HolderBindingResult> {
  const invalid = (detail: string) => failure(ErrorCodes.KB_INVALID, detail);
  if (sdJwt.kbJwt === null) return invalid('KB-JWT missing');
  const cnf = sdJwt.payload['cnf'] as { jwk?: unknown } | undefined;
  const holderKey = normalizeEcPublicJwk(cnf?.jwk);
  if (!holderKey) return invalid('credential has no EC P-256 cnf.jwk');
  const kb = decodeJws(sdJwt.kbJwt, SD_JWT_LIMITS.maxKbJwtBytes);
  if (!kb.ok) return invalid('KB-JWT is not a compact JWS of at most 4096 bytes');
  if (kb.jws.header['typ'] !== 'kb+jwt') return invalid('KB-JWT typ is not kb+jwt');
  // The signature comes first, so an unsigned KB-JWT can never produce a nonce or aud "mismatch".
  const signature = await verifyJws(kb.jws, holderKey, verifier);
  if (signature === 'ALG_NOT_ALLOWED') return invalid('KB-JWT alg is not ES256');
  if (signature !== null) return invalid('KB-JWT signature does not verify with cnf.jwk');
  let claims: unknown;
  try {
    claims = JSON.parse(utf8Decode(kb.jws.payload));
  } catch {
    return invalid('KB-JWT payload is not JSON');
  }
  if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) return invalid('KB-JWT payload is not a JSON object');
  const c = claims as Record<string, unknown>;
  const sdHash = await sdHashOf(sdJwt.withoutKb, hasher);
  if (c['sd_hash'] !== sdHash) return invalid('sd_hash does not match the presented SD-JWT');
  const iat = c['iat'];
  const t = now.getTime() / 1000;
  const skew = SD_JWT_LIMITS.clockSkewSeconds;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return invalid('KB-JWT iat missing');
  if (iat > t + skew) return invalid('KB-JWT iat is in the future');
  if (iat < t - SD_JWT_LIMITS.kbMaxAgeSeconds - skew) return invalid('KB-JWT is too old');
  const exp = c['exp'];
  const nbf = c['nbf'];
  if (exp !== undefined && !(typeof exp === 'number' && Number.isFinite(exp) && exp > t - skew)) return invalid('KB-JWT exp has passed or is not a number');
  if (nbf !== undefined && !(typeof nbf === 'number' && Number.isFinite(nbf) && nbf <= t + skew)) return invalid('KB-JWT nbf is in the future or is not a number');
  if (c['nonce'] !== presentation.nonce) return failure(ErrorCodes.NONCE_MISMATCH, 'KB-JWT nonce differs');
  if (c['aud'] !== presentation.audience) return failure(ErrorCodes.AUD_MISMATCH, 'KB-JWT aud differs');
  return { ok: true, disclosed: {} };
}

/** Disclosure rules, then (for a presentation) the KB-JWT. */
export async function checkHolderBinding(
  sdJwt: ParsedSdJwt,
  options: { verifier: Verifier; hasher: Hasher; now: Date; presentation?: { nonce: string; audience: string } },
): Promise<HolderBindingResult> {
  const disclosures = await checkDisclosures(sdJwt, options.hasher);
  if (!disclosures.ok || !options.presentation) return disclosures;
  const kb = await checkKeyBinding(sdJwt, options.presentation, options.verifier, options.hasher, options.now);
  return kb.ok ? disclosures : kb;
}
