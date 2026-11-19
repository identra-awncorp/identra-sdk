// Structural parsing of an SD-JWT compact `<issuer-jwt>~<disclosure>~...~[<kb-jwt>]` (RFC 9901).
// Nothing here is verified; size limits are checked before any decoding.
import { base64UrlDecode, utf8Decode } from '../encoding.js';
import { decodeJws, type DecodedJws } from '../jws.js';
import { ErrorCodes } from '../results.js';
import { SD_JWT_LIMITS, VCT } from './credential-types.js';

export interface ParsedDisclosure {
  /** The base64url string exactly as received (digest input). */
  encoded: string;
  /** The decoded JSON array: [salt, name, value] for an object property, [salt, value] for an array element. */
  array: unknown[];
}

export interface ParsedSdJwt {
  jws: DecodedJws;
  payload: Record<string, unknown>;
  disclosures: ParsedDisclosure[];
  kbJwt: string | null;
  /** `<issuer-jwt>~<disclosure>~...~`: the input of the KB-JWT `sd_hash`. */
  withoutKb: string;
}

export type ParseSdJwtResult =
  | { ok: true; sdJwt: ParsedSdJwt }
  | { ok: false; code: typeof ErrorCodes.MALFORMED | typeof ErrorCodes.TOO_LARGE; detail: string };

const COMPACT_CHARS = /^[A-Za-z0-9_\-.~]*$/;

function decodeJsonPart(b64: string): unknown {
  return JSON.parse(utf8Decode(base64UrlDecode(b64)));
}

/** Splits and decodes a compact. Never throws. */
export function parseSdJwt(compact: unknown): ParseSdJwtResult {
  const malformed = (detail: string): ParseSdJwtResult => ({ ok: false, code: ErrorCodes.MALFORMED, detail });
  const tooLarge = (detail: string): ParseSdJwtResult => ({ ok: false, code: ErrorCodes.TOO_LARGE, detail });
  if (typeof compact !== 'string') return malformed('not a string');
  // Every UTF-16 unit is at least one UTF-8 byte, and an accepted compact is ASCII, so length = bytes.
  if (compact.length > SD_JWT_LIMITS.maxCompactBytes) return tooLarge(`larger than ${SD_JWT_LIMITS.maxCompactBytes} bytes`);
  let separators = 0;
  for (let i = 0; i < compact.length; i++) if (compact.charCodeAt(i) === 0x7e) separators++;
  if (separators - 1 > SD_JWT_LIMITS.maxDisclosures) return tooLarge(`more than ${SD_JWT_LIMITS.maxDisclosures} disclosures`);
  if (!COMPACT_CHARS.test(compact)) return malformed('characters outside base64url, "." and "~"');

  const parts = compact.split('~');
  if (parts.length < 2) return malformed('no "~" separator');
  const issuerJwt = parts[0]!;
  const last = parts[parts.length - 1]!;
  const encodedDisclosures = parts.slice(1, -1);
  const decoded = decodeJws(issuerJwt, SD_JWT_LIMITS.maxCompactBytes);
  if (!decoded.ok) return malformed(`issuer JWT: ${decoded.detail}`);
  let payload: unknown;
  try {
    payload = JSON.parse(utf8Decode(decoded.jws.payload));
  } catch {
    return malformed('issuer JWT payload is not JSON');
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return malformed('issuer JWT payload is not a JSON object');

  const disclosures: ParsedDisclosure[] = [];
  for (const encoded of encodedDisclosures) {
    if (encoded === '') return malformed('empty disclosure');
    let array: unknown;
    try {
      array = decodeJsonPart(encoded);
    } catch {
      return malformed('disclosure is not base64url JSON');
    }
    if (!Array.isArray(array)) return malformed('disclosure is not a JSON array');
    disclosures.push({ encoded, array });
  }
  // A KB-JWT is checked by the holder-binding step, not here.
  return {
    ok: true,
    sdJwt: {
      jws: decoded.jws,
      payload: payload as Record<string, unknown>,
      disclosures,
      kbJwt: last === '' ? null : last,
      withoutKb: compact.slice(0, compact.length - last.length),
    },
  };
}

const RESERVED_KEYS = ['_sd', '_sd_alg', '...'];
/** Names that would reach an object's prototype machinery when a verifier or consumer copies claims. */
export const PROTOTYPE_NAMES: readonly string[] = Object.freeze(['__proto__', 'constructor', 'prototype']);
/** Nesting levels allowed in the payload and in each disclosure array (`{}` and `[]` are one level). */
export const MAX_JSON_DEPTH = 32;

/** True when `root` nests arrays / objects more than `max` levels deep. Iterative: depth is attacker-chosen. */
export function jsonDepthExceeds(root: unknown, max: number): boolean {
  const stack: [unknown, number][] = [[root, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!;
    if (typeof v !== 'object' || v === null) continue;
    if (depth >= max) return true;
    for (const e of Array.isArray(v) ? v : Object.values(v)) stack.push([e, depth + 1]);
  }
  return false;
}
const DIGEST = /^[A-Za-z0-9_-]{43}$/;

/** True when any object reachable from `roots` (the roots included) has a key `_sd`, `_sd_alg` or `...`. Iterative: depth is attacker-chosen. */
export function containsReservedKey(roots: unknown[]): boolean {
  const stack = [...roots];
  while (stack.length > 0) {
    const v = stack.pop();
    if (Array.isArray(v)) for (const e of v) stack.push(e);
    else if (typeof v === 'object' && v !== null) {
      for (const [k, e] of Object.entries(v)) {
        if (RESERVED_KEYS.includes(k)) return true;
        stack.push(e);
      }
    }
  }
  return false;
}

/**
 * RFC 9901 shape rules for the issuer-signed payload, whatever the disclosures: `_sd` (if present)
 * is an array of unique 43-character base64url digests; `_sd_alg` is `sha-256`, required with
 * `_sd`; no `_sd`, `_sd_alg` or `...` key below the top level (Identra types have no nested or
 * array-element disclosures). Returns the broken rule, or null.
 */
export function sdShapeProblem(payload: Record<string, unknown>): string | null {
  const { _sd: sd, _sd_alg: sdAlg, ...rest } = payload;
  if (sd !== undefined) {
    if (!Array.isArray(sd) || !sd.every((d) => typeof d === 'string' && DIGEST.test(d))) return '_sd is not a list of SHA-256 digests';
    if (new Set(sd).size !== sd.length) return '_sd repeats a digest';
    if (sdAlg !== 'sha-256') return '_sd_alg is not sha-256';
  } else if (sdAlg !== undefined && sdAlg !== 'sha-256') return '_sd_alg is not sha-256';
  if (containsReservedKey(Object.values(rest))) return 'nested or array-element selective disclosure is not supported';
  return null;
}

/** Number of disclosure segments a compact shows when split on "~" (a trailing KB-JWT adds none). */
export function disclosureSegments(compact: unknown): number {
  if (typeof compact !== 'string') return 0;
  let separators = 0;
  for (let i = 0; i < compact.length; i++) if (compact.charCodeAt(i) === 0x7e) separators++;
  return Math.max(separators - 1, 0);
}

export interface UnverifiedCredential {
  header: Record<string, unknown>;
  /** The issuer-signed payload as is, including `_sd` and `_sd_alg`. */
  payload: Record<string, unknown>;
  /** Object-property disclosures carried by the compact. Not checked against `_sd`. */
  disclosures: { name: string; value: unknown }[];
  isProductEvent: boolean;
}

/**
 * NOT VERIFICATION. Decodes a credential the wallet already holds, for display only: no signature,
 * certificate, digest, time, trust or status check is made, so nothing returned here may be used
 * for a decision. Use verifyStoredCredential or verifyPresentation for that. Throws TypeError on a malformed compact.
 */
export function decodeCredentialUnverified(compact: string): UnverifiedCredential {
  const r = parseSdJwt(compact);
  if (!r.ok) throw new TypeError(`not an SD-JWT compact (${r.detail})`);
  const { jws, payload, disclosures } = r.sdJwt;
  return {
    header: jws.header,
    payload,
    disclosures: disclosures
      .filter((d) => d.array.length === 3 && typeof d.array[1] === 'string')
      .map((d) => ({ name: d.array[1] as string, value: d.array[2] })),
    isProductEvent: payload['vct'] === VCT.productEvent,
  };
}
