// JWS compact serialization (RFC 7515). The signing input and the compact form are built
// here and nowhere else (ADR-0006, "Hệ quả"). `alg` is never used to pick an algorithm:
// only ES256 exists and the key type comes from the JWK.
import { base64UrlDecode, base64UrlEncode, utf8Decode, utf8Encode } from './encoding.js';
import type { EcPublicJwk, Signer, Verifier } from './interfaces.js';
import { ErrorCodes } from './results.js';

export const ALLOWED_JWS_ALGORITHMS: readonly string[] = Object.freeze(['ES256']);

export interface DecodedJws {
  header: Record<string, unknown>;
  payload: Uint8Array;
  signature: Uint8Array;
  /** ASCII bytes of `<header>.<payload>`, exactly as received. */
  signingInput: Uint8Array;
}

export type DecodeJwsResult =
  | { ok: true; jws: DecodedJws }
  | { ok: false; code: typeof ErrorCodes.MALFORMED | typeof ErrorCodes.TOO_LARGE; detail: string };

/**
 * Signs `payload` with `signer` and returns the compact JWS. `alg` comes from the signer, `x5c` is
 * added when the signer has one, and so is `kid` when the signer's `kid` is a DID URL (ADR-0020,
 * never together with `x5c`); the caller must not set any of them.
 */
export async function signJws(protectedHeader: Record<string, unknown>, payload: Uint8Array, signer: Signer): Promise<string> {
  if ('alg' in protectedHeader || 'x5c' in protectedHeader) {
    throw new TypeError('protectedHeader must not contain alg or x5c; they come from the signer');
  }
  if (signer.alg !== 'ES256') throw new TypeError('only ES256 signers are supported');
  const header: Record<string, unknown> = { alg: signer.alg, ...protectedHeader };
  if (typeof signer.kid === 'string' && signer.kid.startsWith('did:')) {
    if (signer.x5c !== undefined) throw new TypeError('a signer carries x5c or a DID kid, never both');
    if ('kid' in protectedHeader) throw new TypeError('protectedHeader must not contain kid; a DID kid comes from the signer');
    header['kid'] = signer.kid;
  }
  if (signer.x5c) header['x5c'] = [...signer.x5c];
  const input = `${base64UrlEncode(utf8Encode(JSON.stringify(header)))}.${base64UrlEncode(payload)}`;
  const signature = await signer.sign(utf8Encode(input));
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new TypeError('signer must return a 64-byte r||s signature');
  }
  return `${input}.${base64UrlEncode(signature)}`;
}

/**
 * Strict compact JWS decoding: at most `maxBytes` long (checked first, `TOO_LARGE`), exactly
 * three non-empty base64url parts and a header that is a JSON object. Never throws for bad
 * input. A `crit` header is rejected because no extension is understood. Nothing about `alg` is
 * decided here (see verifyJws).
 */
export function decodeJws(compact: unknown, maxBytes: number): DecodeJwsResult {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new TypeError('maxBytes must be a positive integer');
  const fail = (detail: string): DecodeJwsResult => ({ ok: false, code: ErrorCodes.MALFORMED, detail });
  if (typeof compact !== 'string') return fail('not a string');
  // Every UTF-16 unit is at least one UTF-8 byte; anything non-ASCII fails base64url below.
  if (compact.length > maxBytes) return { ok: false, code: ErrorCodes.TOO_LARGE, detail: `larger than ${maxBytes} bytes` };
  const parts = compact.split('.');
  if (parts.length !== 3) return fail('expected three parts');
  const [h, p, s] = parts as [string, string, string];
  if (!h || !p || !s) return fail('empty part');
  let header: unknown;
  let payload: Uint8Array;
  let signature: Uint8Array;
  try {
    header = JSON.parse(utf8Decode(base64UrlDecode(h)));
    payload = base64UrlDecode(p);
    signature = base64UrlDecode(s);
  } catch {
    return fail('invalid base64url, UTF-8 or JSON');
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return fail('header is not a JSON object');
  if ('crit' in header) return fail('crit header is not supported');
  return {
    ok: true,
    jws: { header: header as Record<string, unknown>, payload, signature, signingInput: utf8Encode(`${h}.${p}`) },
  };
}

/** The algorithm allow-list check: null when `alg` is ES256, ALG_NOT_ALLOWED otherwise. */
export function checkJwsAlgorithm(header: Record<string, unknown>): typeof ErrorCodes.ALG_NOT_ALLOWED | null {
  const alg = header['alg'];
  return typeof alg === 'string' && ALLOWED_JWS_ALGORITHMS.includes(alg) ? null : ErrorCodes.ALG_NOT_ALLOWED;
}

/**
 * The one verification of a decoded JWS: the `alg` allow-list (ES256 only) and then the ES256
 * signature with a P-256 key. The key type comes from the JWK, never from the header.
 * Returns null when both pass. Never throws for bad input.
 */
export async function verifyJws(
  jws: DecodedJws,
  publicJwk: EcPublicJwk,
  verifier: Verifier,
): Promise<null | typeof ErrorCodes.ALG_NOT_ALLOWED | typeof ErrorCodes.SIGNATURE_INVALID> {
  if (checkJwsAlgorithm(jws.header) !== null) return ErrorCodes.ALG_NOT_ALLOWED;
  if (jws.signature.length !== 64) return ErrorCodes.SIGNATURE_INVALID;
  return (await verifier.verify(publicJwk, jws.signingInput, jws.signature)) ? null : ErrorCodes.SIGNATURE_INVALID;
}
