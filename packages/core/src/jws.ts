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

export type DecodeJwsResult = { ok: true; jws: DecodedJws } | { ok: false; code: typeof ErrorCodes.MALFORMED; detail: string };

/**
 * Signs `payload` with `signer` and returns the compact JWS. `alg` comes from the signer and
 * `x5c` is added when the signer has one; the caller must not set either.
 */
export async function signJws(protectedHeader: Record<string, unknown>, payload: Uint8Array, signer: Signer): Promise<string> {
  if ('alg' in protectedHeader || 'x5c' in protectedHeader) {
    throw new TypeError('protectedHeader must not contain alg or x5c; they come from the signer');
  }
  if (signer.alg !== 'ES256') throw new TypeError('only ES256 signers are supported');
  const header: Record<string, unknown> = { alg: signer.alg, ...protectedHeader };
  if (signer.x5c) header['x5c'] = [...signer.x5c];
  const input = `${base64UrlEncode(utf8Encode(JSON.stringify(header)))}.${base64UrlEncode(payload)}`;
  const signature = await signer.sign(utf8Encode(input));
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new TypeError('signer must return a 64-byte r||s signature');
  }
  return `${input}.${base64UrlEncode(signature)}`;
}

/**
 * Strict compact JWS decoding: exactly three non-empty base64url parts and a header that is a
 * JSON object. Never throws for bad input. A `crit` header is rejected because no extension
 * is understood. Nothing about `alg` is decided here (see checkJwsAlgorithm).
 */
export function decodeJws(compact: unknown): DecodeJwsResult {
  const fail = (detail: string): DecodeJwsResult => ({ ok: false, code: ErrorCodes.MALFORMED, detail });
  if (typeof compact !== 'string') return fail('not a string');
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
 * ES256 signature check of a decoded JWS with a P-256 key. The header (including `alg`) is not
 * consulted; callers run checkJwsAlgorithm first. Returns false for any bad input.
 */
export async function verifyJwsSignature(jws: DecodedJws, publicJwk: EcPublicJwk, verifier: Verifier): Promise<boolean> {
  if (jws.signature.length !== 64) return false;
  return verifier.verify(publicJwk, jws.signingInput, jws.signature);
}
