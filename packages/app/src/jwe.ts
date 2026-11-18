// Compact JWE for OpenID4VCI credential response encryption and OpenID4VP direct_post.jwt:
// alg ECDH-ES (direct key agreement, P-256 ephemeral-static, RFC 7518 section 4.6) with
// enc A128GCM or A256GCM. Nothing else: no key wrapping, no AES-CBC, no other curve, no zip.
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode, concatBytes, utf8Decode, utf8Encode } from '@identra/sdk-core';
import type { EcPublicJwk, RandomSource } from '@identra/sdk-core';
import { generateSecretKey, P256, publicPointOf, uncompressedPointToJwk } from './crypto/noble.js';
import { drawRandom } from './random.js';

export type JweEnc = 'A128GCM' | 'A256GCM';

const KEY_BYTES: Record<JweEnc, number> = { A128GCM: 16, A256GCM: 32 };
const IV_BYTES = 12;
const TAG_BYTES = 16;
/**
 * Upper bound on a compact JWE accepted by decryptJwe, checked before any parsing. With a typical
 * header this admits plaintexts up to about 48 954 bytes (measured); one credential is a few KB.
 * Batch issuance (ADR-0014 section 3, a later phase) may need a larger bound.
 */
export const MAX_JWE_LENGTH = 65536;

/** Members a protected header may carry. Anything else (zip, crit, jku, ...) is rejected. */
const HEADER_MEMBERS = new Set(['alg', 'enc', 'epk', 'apu', 'apv', 'kid', 'typ', 'cty']);
const OPTIONAL_STRING_MEMBERS = ['kid', 'typ', 'cty'] as const;

export interface JweHeader {
  alg: 'ECDH-ES';
  enc: JweEnc;
  epk: EcPublicJwk;
  apu?: string;
  apv?: string;
  kid?: string;
  typ?: string;
  cty?: string;
}

/**
 * Decryption failure. `code` is 'JWE_INVALID' for input that is not a JWE this module accepts and
 * 'JWE_DECRYPTION_FAILED' when the key agreement or authentication fails. The message never says
 * more than the code. The code is for local logs and UI: do not forward it to the remote party.
 */
export class JweError extends Error {
  readonly code: 'JWE_INVALID' | 'JWE_DECRYPTION_FAILED';
  constructor(code: 'JWE_INVALID' | 'JWE_DECRYPTION_FAILED') {
    super(code === 'JWE_INVALID' ? 'invalid JWE' : 'JWE decryption failed');
    this.name = 'JweError';
    this.code = code;
  }
}

const u32be = (n: number): Uint8Array => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
const lengthPrefixed = (b: Uint8Array): Uint8Array => concatBytes(u32be(b.length), b);

/**
 * Concat KDF (NIST SP 800-56A, RFC 7518 section 4.6.2) for direct key agreement: AlgorithmID is
 * the `enc` value, SuppPrivInfo is empty. One SHA-256 round gives the at most 256 bits needed.
 */
function concatKdf(z: Uint8Array, enc: JweEnc, apu: Uint8Array, apv: Uint8Array): Uint8Array {
  const keyBytes = KEY_BYTES[enc];
  const input = concatBytes(u32be(1), z, lengthPrefixed(utf8Encode(enc)), lengthPrefixed(apu), lengthPrefixed(apv), u32be(keyBytes * 8));
  const digest = sha256(input);
  input.fill(0);
  const key = digest.slice(0, keyBytes);
  digest.fill(0);
  return key;
}

/** x-coordinate of d * Q. Q has been validated as an on-curve, non-identity P-256 point. */
function sharedSecret(secretKey: Uint8Array, point: Uint8Array): Uint8Array {
  const shared = P256.getSharedSecret(secretKey, point, true);
  const z = shared.slice(1);
  shared.fill(0);
  // Unreachable with a valid scalar on a prime-order curve; checked anyway, without branching on
  // individual secret bytes.
  let acc = 0;
  for (const b of z) acc |= b;
  if (acc === 0) throw new JweError('JWE_DECRYPTION_FAILED');
  return z;
}

function isBase64Url(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  try {
    base64UrlDecode(v);
    return true;
  } catch {
    return false;
  }
}

/** ECDH-ES + A128GCM / A256GCM compact JWE. The ephemeral key and the IV come from `random`. */
export function encryptJwe(input: {
  recipientPublicJwk: EcPublicJwk;
  enc: JweEnc;
  plaintext: Uint8Array;
  random: RandomSource;
  header?: { kid?: string; apu?: string; apv?: string; typ?: string; cty?: string };
}): string {
  const { enc, plaintext, random, header = {} } = input;
  const recipient = publicPointOf(input.recipientPublicJwk);
  if (!recipient) throw new TypeError('recipientPublicJwk must be a valid EC P-256 public key');
  if (enc !== 'A128GCM' && enc !== 'A256GCM') throw new TypeError('enc must be A128GCM or A256GCM');
  if (!(plaintext instanceof Uint8Array)) throw new TypeError('plaintext must be a Uint8Array');
  for (const m of OPTIONAL_STRING_MEMBERS) {
    if (header[m] !== undefined && typeof header[m] !== 'string') throw new TypeError(`header.${m} must be a string`);
  }
  for (const m of ['apu', 'apv'] as const) {
    if (header[m] !== undefined && !isBase64Url(header[m])) throw new TypeError(`header.${m} must be base64url`);
  }
  // jose refuses a JWE whose apu equals apv; an empty value is simply left out.
  const apu = header.apu || undefined;
  const apv = header.apv || undefined;
  if (apu !== undefined && apu === apv) throw new TypeError('header.apu and header.apv must differ');

  const ephemeral = generateSecretKey(random);
  let z: Uint8Array | undefined;
  let cek: Uint8Array | undefined;
  try {
    const protectedHeader: JweHeader = { alg: 'ECDH-ES', enc, epk: uncompressedPointToJwk(P256.getPublicKey(ephemeral, false)) };
    if (apu !== undefined) protectedHeader.apu = apu;
    if (apv !== undefined) protectedHeader.apv = apv;
    for (const m of OPTIONAL_STRING_MEMBERS) if (header[m] !== undefined) protectedHeader[m] = header[m];
    z = sharedSecret(ephemeral, recipient);
    cek = concatKdf(z, enc, base64UrlDecode(apu ?? ''), base64UrlDecode(apv ?? ''));
    const iv = drawRandom(random, IV_BYTES);
    const encodedHeader = base64UrlEncode(utf8Encode(JSON.stringify(protectedHeader)));
    const sealed = gcm(cek, iv, utf8Encode(encodedHeader)).encrypt(plaintext);
    const ciphertext = sealed.subarray(0, sealed.length - TAG_BYTES);
    const tag = sealed.subarray(sealed.length - TAG_BYTES);
    return [encodedHeader, '', base64UrlEncode(iv), base64UrlEncode(ciphertext), base64UrlEncode(tag)].join('.');
  } finally {
    ephemeral.fill(0);
    z?.fill(0);
    cek?.fill(0);
  }
}

/** Strict parse of the protected header; null when it is not one this module accepts. */
function parseHeader(encoded: string): { header: JweHeader; epkPoint: Uint8Array } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(base64UrlDecode(encoded)));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const h = parsed as Record<string, unknown>;
  if (!Object.keys(h).every((k) => HEADER_MEMBERS.has(k))) return null;
  if (h['alg'] !== 'ECDH-ES') return null;
  const enc = h['enc'];
  if (enc !== 'A128GCM' && enc !== 'A256GCM') return null;
  // Invalid-curve defence, two layers before any ECDH: sdk-core's JWK check (on-curve P-256) and
  // noble's public-key validation (on-curve, not the identity).
  const epkPoint = publicPointOf(h['epk']);
  if (!epkPoint || !P256.utils.isValidPublicKey(epkPoint, false)) return null;
  const header: JweHeader = { alg: 'ECDH-ES', enc, epk: uncompressedPointToJwk(epkPoint) };
  for (const m of ['apu', 'apv'] as const) {
    const v = h[m];
    if (v === undefined) continue;
    if (!isBase64Url(v)) return null;
    header[m] = v;
  }
  for (const m of OPTIONAL_STRING_MEMBERS) {
    const v = h[m];
    if (v === undefined) continue;
    if (typeof v !== 'string') return null;
    header[m] = v;
  }
  return { header, epkPoint };
}

function decodePart(part: string, length?: number): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(part);
  } catch {
    throw new JweError('JWE_INVALID');
  }
  if (length !== undefined && bytes.length !== length) throw new JweError('JWE_INVALID');
  return bytes;
}

/**
 * Decrypts a compact ECDH-ES + A128GCM / A256GCM JWE. Throws JweError on any failure; TypeError
 * when `recipientSecretKey` is not a valid P-256 secret key (programmer error).
 */
export function decryptJwe(input: { jwe: string; recipientSecretKey: Uint8Array }): { plaintext: Uint8Array; header: JweHeader } {
  const { jwe, recipientSecretKey } = input;
  if (!(recipientSecretKey instanceof Uint8Array) || !P256.utils.isValidSecretKey(recipientSecretKey)) {
    throw new TypeError('recipientSecretKey must be a valid 32-byte P-256 secret key');
  }
  if (typeof jwe !== 'string' || jwe.length > MAX_JWE_LENGTH) throw new JweError('JWE_INVALID');
  const parts = jwe.split('.');
  if (parts.length !== 5) throw new JweError('JWE_INVALID');
  const [encodedHeader, encryptedKey, encodedIv, encodedCiphertext, encodedTag] = parts as [string, string, string, string, string];
  if (encryptedKey !== '') throw new JweError('JWE_INVALID');
  const parsed = parseHeader(encodedHeader);
  if (!parsed) throw new JweError('JWE_INVALID');
  const { header, epkPoint } = parsed;
  const iv = decodePart(encodedIv, IV_BYTES);
  const ciphertext = decodePart(encodedCiphertext);
  const tag = decodePart(encodedTag, TAG_BYTES);

  let z: Uint8Array | undefined;
  let cek: Uint8Array | undefined;
  try {
    z = sharedSecret(recipientSecretKey, epkPoint);
    cek = concatKdf(z, header.enc, base64UrlDecode(header.apu ?? ''), base64UrlDecode(header.apv ?? ''));
    const plaintext = gcm(cek, iv, utf8Encode(encodedHeader)).decrypt(concatBytes(ciphertext, tag));
    return { plaintext, header };
  } catch {
    throw new JweError('JWE_DECRYPTION_FAILED');
  } finally {
    z?.fill(0);
    cek?.fill(0);
  }
}
