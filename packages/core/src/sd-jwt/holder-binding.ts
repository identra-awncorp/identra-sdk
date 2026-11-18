// Step 9 of the verification policy: disclosures (ADR-0008 section 6) and the KB-JWT (section 4).
// Our own code on purpose: the library cannot report which rule failed, lets `iat` through as a
// disclosure and does not compare `sd_hash` (ADR-0004, "Bổ sung 2026-11-19" point 3).
import { base64UrlEncode, utf8Decode, utf8Encode } from '../encoding.js';
import type { Hasher, Verifier } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { checkJwsAlgorithm, decodeJws, verifyJwsSignature } from '../jws.js';
import { ErrorCodes, type ErrorCode } from '../results.js';
import type { ParsedSdJwt } from './compact.js';
import { METADATA_CLAIMS, RESERVED_CLAIM_NAMES, SD_JWT_LIMITS } from './credential-types.js';

export type HolderBindingResult =
  | { ok: true; disclosed: Record<string, unknown> }
  | { ok: false; code: ErrorCode; detail: string };

const failure = (code: ErrorCode, detail: string): HolderBindingResult => ({ ok: false, code, detail });

const isArrayElementDigest = (v: unknown): boolean =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 1 && '...' in v;

/** True when any value holds a nested `_sd` or an array-element digest. Iterative: payload depth is attacker-chosen. */
function hasNestedSelectiveDisclosure(roots: unknown[]): boolean {
  const stack = [...roots];
  while (stack.length > 0) {
    const v = stack.pop();
    if (Array.isArray(v)) {
      for (const e of v) {
        if (isArrayElementDigest(e)) return true;
        stack.push(e);
      }
    } else if (typeof v === 'object' && v !== null) {
      if ('_sd' in v) return true;
      for (const e of Object.values(v)) stack.push(e);
    }
  }
  return false;
}

async function checkDisclosures(sdJwt: ParsedSdJwt, hasher: Hasher): Promise<HolderBindingResult> {
  const invalid = (detail: string) => failure(ErrorCodes.DISCLOSURE_INVALID, detail);
  const { payload, disclosures } = sdJwt;
  const { _sd: sd, _sd_alg: sdAlg, ...plain } = payload;
  if (disclosures.length > 0) {
    if (sdAlg !== 'sha-256') return invalid('_sd_alg is not sha-256');
    if (!Array.isArray(sd) || !sd.every((d) => typeof d === 'string')) return invalid('payload has no _sd digest list');
  }
  const digests = new Set<string>();
  // No prototype: a disclosure named __proto__ stays a plain data property.
  const disclosed: Record<string, unknown> = Object.create(null);
  for (const d of disclosures) {
    if (d.array.length !== 3) return invalid('array-element disclosures are not supported');
    const [salt, name, value] = d.array;
    if (typeof salt !== 'string' || typeof name !== 'string') return invalid('disclosure salt and name must be strings');
    if (RESERVED_CLAIM_NAMES.includes(name)) return invalid('disclosure uses a reserved name');
    if (METADATA_CLAIMS.includes(name)) return invalid('metadata claim delivered by a disclosure');
    const digest = base64UrlEncode(await hasher.sha256(utf8Encode(d.encoded)));
    if (digests.has(digest)) return invalid('duplicate disclosure');
    digests.add(digest);
    if (!(sd as string[]).includes(digest)) return invalid('disclosure is not referenced by _sd');
    if (Object.keys(disclosed).includes(name)) return invalid('two disclosures for one claim name');
    if (Object.keys(payload).includes(name)) return invalid('disclosure clashes with a payload claim');
    disclosed[name] = value;
  }
  if (hasNestedSelectiveDisclosure([plain, ...Object.values(disclosed)])) {
    return invalid('nested or array-element selective disclosure is not supported');
  }
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
  const kb = decodeJws(sdJwt.kbJwt);
  if (!kb.ok) return invalid('KB-JWT is not a compact JWS');
  if (kb.jws.header['typ'] !== 'kb+jwt') return invalid('KB-JWT typ is not kb+jwt');
  if (checkJwsAlgorithm(kb.jws.header) !== null) return invalid('KB-JWT alg is not ES256');
  // The signature comes first, so an unsigned KB-JWT can never produce a nonce or aud "mismatch".
  if (!(await verifyJwsSignature(kb.jws, holderKey, verifier))) return invalid('KB-JWT signature does not verify with cnf.jwk');
  let claims: unknown;
  try {
    claims = JSON.parse(utf8Decode(kb.jws.payload));
  } catch {
    return invalid('KB-JWT payload is not JSON');
  }
  if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) return invalid('KB-JWT payload is not a JSON object');
  const c = claims as Record<string, unknown>;
  const sdHash = base64UrlEncode(await hasher.sha256(utf8Encode(sdJwt.withoutKb)));
  if (c['sd_hash'] !== sdHash) return invalid('sd_hash does not match the presented SD-JWT');
  const iat = c['iat'];
  const t = now.getTime() / 1000;
  const skew = SD_JWT_LIMITS.clockSkewSeconds;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return invalid('KB-JWT iat missing');
  if (iat > t + skew) return invalid('KB-JWT iat is in the future');
  if (iat < t - SD_JWT_LIMITS.kbMaxAgeSeconds - skew) return invalid('KB-JWT is too old');
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
