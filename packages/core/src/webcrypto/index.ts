// @identra/sdk-core/webcrypto: Signer / Verifier / Hasher / RandomSource on globalThis.crypto
// (Node >= 22, browsers). The only file of sdk-core allowed to use globalThis.crypto.
// React Native has no WebCrypto and must not import this entry.
import { base64Decode } from '../encoding.js';
import type { EcPublicJwk, Hasher, RandomSource, Signer, Verifier } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { parseCertificate } from '../x509/parse.js';

const KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;
const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

/** Accepts low-S and high-S signatures (WebCrypto does not normalise S). Never throws. */
export const webCryptoVerifier: Verifier = {
  async verify(publicJwk, data, signature) {
    const jwk = normalizeEcPublicJwk(publicJwk);
    if (!jwk || !(data instanceof Uint8Array) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
    try {
      const key = await subtle().importKey('jwk', jwk, KEY_ALG, false, ['verify']);
      return await subtle().verify(SIGN_ALG, key, signature, data);
    } catch {
      return false;
    }
  },
};

export const webCryptoHasher: Hasher = {
  async sha256(data) {
    return new Uint8Array(await subtle().digest('SHA-256', data));
  },
};

export const webCryptoRandom: RandomSource = {
  bytes(n) {
    return globalThis.crypto.getRandomValues(new Uint8Array(n));
  },
};

function pemToPkcs8(pem: string): Uint8Array {
  const m = /^-----BEGIN PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PRIVATE KEY-----\r?\n?$/.exec(pem.trim() + '\n');
  if (!m) throw new TypeError('privateKey PEM must be a single PKCS#8 "PRIVATE KEY" block');
  return base64Decode(m[1]!.replace(/\r?\n/g, ''));
}

async function publicJwkOf(privateKey: CryptoKey): Promise<EcPublicJwk> {
  const { kty, crv, x, y } = await subtle().exportKey('jwk', privateKey);
  const jwk = normalizeEcPublicJwk({ kty, crv, x, y });
  if (!jwk) throw new TypeError('privateKey is not an EC P-256 key');
  return jwk;
}

/**
 * ES256 Signer from a PKCS#8 private key (PEM string or DER bytes) or an extractable ECDSA P-256
 * CryptoKey (needed to derive the public key). When `x5c` is given, its first certificate must
 * hold the matching public key.
 */
export async function createWebCryptoSigner(options: { privateKey: CryptoKey | string | Uint8Array; x5c?: string[] }): Promise<Signer> {
  const { privateKey, x5c } = options;
  let key: CryptoKey;
  let publicJwk: EcPublicJwk;
  if (typeof privateKey === 'string' || privateKey instanceof Uint8Array) {
    const pkcs8 = typeof privateKey === 'string' ? pemToPkcs8(privateKey) : privateKey;
    publicJwk = await publicJwkOf(await subtle().importKey('pkcs8', pkcs8, KEY_ALG, true, ['sign']));
    key = await subtle().importKey('pkcs8', pkcs8, KEY_ALG, false, ['sign']);
  } else {
    const alg = privateKey.algorithm as EcKeyAlgorithm;
    if (privateKey.type !== 'private' || alg.name !== 'ECDSA' || alg.namedCurve !== 'P-256' || !privateKey.usages.includes('sign')) {
      throw new TypeError('privateKey must be an ECDSA P-256 private key usable for signing');
    }
    if (!privateKey.extractable) throw new TypeError('privateKey CryptoKey must be extractable to derive its public key');
    key = privateKey;
    publicJwk = await publicJwkOf(privateKey);
  }
  if (x5c !== undefined) {
    if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((c) => typeof c === 'string')) throw new TypeError('x5c must be a non-empty array of base64 certificates');
    const leafKey = parseCertificate(base64Decode(x5c[0]!)).publicJwk;
    if (!leafKey || leafKey.x !== publicJwk.x || leafKey.y !== publicJwk.y) throw new TypeError('x5c[0] does not hold the public key of privateKey');
  }
  const signer: Signer = {
    alg: 'ES256',
    publicJwk,
    async sign(data) {
      return new Uint8Array(await subtle().sign(SIGN_ALG, key, data));
    },
  };
  if (x5c !== undefined) signer.x5c = [...x5c];
  return signer;
}

/** Fresh P-256 key pair for tests and development; the private key is extractable. */
export async function generateWebCryptoKeyPair(): Promise<{ privateKey: CryptoKey; publicJwk: EcPublicJwk }> {
  const pair = await subtle().generateKey(KEY_ALG, true, ['sign', 'verify']);
  return { privateKey: pair.privateKey, publicJwk: await publicJwkOf(pair.privateKey) };
}
