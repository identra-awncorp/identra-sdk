// Second crypto backend for the tests: @noble/curves and @noble/hashes (pure JS, as on React
// Native). These adapters move to @identra/sdk-app in a later phase.
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode, normalizeEcPublicJwk, type EcPublicJwk, type Hasher, type Signer, type Verifier } from '@identra/sdk-core';

/** Order of the P-256 group, taken from noble rather than typed by hand. */
export const P256_N: bigint = p256.Point.CURVE().n;

function jwkToPoint(jwk: EcPublicJwk): Uint8Array {
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(base64UrlDecode(jwk.x), 1);
  point.set(base64UrlDecode(jwk.y), 33);
  return point;
}

/** lowS: false is required: noble defaults to rejecting high-S, which OpenSSL produces. */
export const nobleVerifier: Verifier = {
  async verify(publicJwk, data, signature) {
    try {
      // Same key validation as the WebCrypto adapter: EC P-256 public JWK, on the curve.
      const jwk = normalizeEcPublicJwk(publicJwk);
      if (!jwk || !(data instanceof Uint8Array) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
      return p256.verify(signature, data, jwkToPoint(jwk), { lowS: false, prehash: true, format: 'compact' });
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

export function nobleSigner(secretKey: Uint8Array): Signer {
  const point = p256.getPublicKey(secretKey, false);
  return {
    alg: 'ES256',
    publicJwk: { kty: 'EC', crv: 'P-256', x: base64UrlEncode(point.subarray(1, 33)), y: base64UrlEncode(point.subarray(33)) },
    async sign(data) {
      return p256.sign(data, secretKey, { prehash: true, format: 'compact' });
    },
  };
}
