// ES256 crypto adapters on @noble/* (pure JavaScript, React Native / Hermes and Node), the sibling
// of @identra/sdk-core/webcrypto (docs/architecture.md section 2, ADR-0006).
//
// No implicit randomness: noble's ready-made `p256` probes globalThis.crypto when it is imported
// and then draws from it to blind scalar multiplications. This module builds its own P-256
// instance whose RNG hook always fails, so noble falls back to its unblinded constant-time path
// and never touches a global. Every random byte comes from an injected RandomSource.
import { ecdsa, weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode, derSignatureToRaw, hexDecode, hexEncode, normalizeEcPublicJwk } from '@identra/sdk-core';
import type { EcPublicJwk, Hasher, RandomSource, Signer, Verifier } from '@identra/sdk-core';
import { drawRandom } from '../random.js';

const noImplicitRandomness = (): Uint8Array => {
  throw new Error('implicit randomness is disabled');
};

// P-256 domain parameters (SEC 2 / FIPS 186-5), copied from @noble/curves 2.4.0 nist.js; a test
// checks them against noble's own p256 export.
const P256_POINT = weierstrass(
  {
    p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
    n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    h: BigInt(1),
    a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
    b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    Gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
    Gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  },
  { randomBytes: noImplicitRandomness },
);

/** The P-256 / SHA-256 ECDSA instance shared by this package. Internal: not exported from the entry. */
export const P256 = ecdsa(P256_POINT, sha256, { randomBytes: noImplicitRandomness });

/** Seed length noble's hash-to-scalar mapping requires for P-256 (1.5x the order length); noble checks it. */
const SEED_BYTES = 48;

/** 0x04 || x || y for a JWK that passed normalizeEcPublicJwk. Not checked for being on the curve. */
export function jwkToUncompressedPoint(jwk: EcPublicJwk): Uint8Array {
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(base64UrlDecode(jwk.x), 1);
  point.set(base64UrlDecode(jwk.y), 33);
  return point;
}

export function uncompressedPointToJwk(point: Uint8Array): EcPublicJwk {
  return { kty: 'EC', crv: 'P-256', x: base64UrlEncode(point.subarray(1, 33)), y: base64UrlEncode(point.subarray(33, 65)) };
}

/**
 * The public point of a JWK that sdk-core's normalizeEcPublicJwk accepts (P-256, strict
 * coordinates, on the curve; it never throws), or null.
 */
export function publicPointOf(publicJwk: unknown): Uint8Array | null {
  const jwk = normalizeEcPublicJwk(publicJwk);
  return jwk ? jwkToUncompressedPoint(jwk) : null;
}

/** P-256 / SHA-256, low-S and high-S accepted (OpenSSL does not normalise S). Never throws. */
export const nobleVerifier: Verifier = {
  async verify(publicJwk, data, signature) {
    try {
      if (!(data instanceof Uint8Array) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
      const point = publicPointOf(publicJwk);
      if (!point) return false;
      return P256.verify(signature, data, point, { lowS: false, prehash: true, format: 'compact' });
    } catch {
      return false;
    }
  },
};

export const nobleHasher: Hasher = {
  async sha256(data) {
    return sha256(data);
  },
};

/**
 * A fresh P-256 secret key from the injected RandomSource: 48 random bytes mapped into [1, n-1]
 * with noble's documented hash-to-scalar utility (mapHashToField, bias about 2^-128). One draw,
 * no loop, so a broken source cannot hang it; all-equal or repeated output is refused
 * (RandomSourceError, see drawRandom) and anything else gives a valid scalar.
 */
export function generateSecretKey(random: RandomSource): Uint8Array {
  const seed = drawRandom(random, SEED_BYTES);
  try {
    return P256.utils.randomSecretKey(seed);
  } finally {
    seed.fill(0);
  }
}

/**
 * ES256 Signer over a 32-byte P-256 secret key. Signing is deterministic (RFC 6979) and the
 * output is always the low-S 64-byte r||s form. The public JWK is derived from the key; there is
 * no x5c (wallet keys have none).
 *
 * The signer keeps its own copy of the key, so the caller may zero its buffer afterwards. That
 * copy and noble's BigInt intermediates live until garbage collection: JavaScript gives no way to
 * erase them, so zeroing is best-effort only.
 */
export function createNobleSigner(secretKey: Uint8Array, opts: { kid?: string } = {}): Signer {
  if (!(secretKey instanceof Uint8Array) || !P256.utils.isValidSecretKey(secretKey)) {
    throw new TypeError('secretKey must be a valid 32-byte P-256 secret key');
  }
  if (opts.kid !== undefined && typeof opts.kid !== 'string') throw new TypeError('kid must be a string');
  const key = secretKey.slice();
  const signer: Signer = {
    alg: 'ES256',
    publicJwk: uncompressedPointToJwk(P256.getPublicKey(key, false)),
    async sign(data) {
      return P256.sign(data, key, { prehash: true, lowS: true, format: 'compact' });
    },
  };
  if (opts.kid !== undefined) signer.kid = opts.kid;
  return signer;
}

const N = P256.Point.Fn.ORDER;

/**
 * Signer for hardware keystores (Secure Enclave, Android Keystore) whose sign call returns a DER
 * ECDSA signature. The DER is converted to r||s with sdk-core's strict converter and S is
 * normalised to low-S (s > n/2 becomes n - s), like the software signer: hardware returns high-S
 * about half the time and strict third-party verifiers refuse it.
 */
export function createDerSigningAdapter(input: { publicJwk: EcPublicJwk; signDer(data: Uint8Array): Promise<Uint8Array> }): Signer {
  const point = publicPointOf(input.publicJwk);
  if (!point) throw new TypeError('publicJwk must be a valid EC P-256 public key');
  if (typeof input.signDer !== 'function') throw new TypeError('signDer must be a function');
  const signDer = input.signDer;
  return {
    alg: 'ES256',
    publicJwk: uncompressedPointToJwk(point),
    async sign(data) {
      const raw = derSignatureToRaw(await signDer(data));
      const s = BigInt('0x' + hexEncode(raw.subarray(32)));
      if (s > N >> 1n && s < N) raw.set(hexDecode((N - s).toString(16).padStart(64, '0')), 32);
      return raw;
    },
  };
}
