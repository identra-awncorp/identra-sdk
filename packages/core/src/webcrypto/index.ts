// @identra/sdk-core/webcrypto: Signer / Verifier / Hasher / RandomSource on globalThis.crypto
// (Node >= 22, browsers). The only file of sdk-core allowed to use globalThis.crypto.
// React Native has no WebCrypto and must not import this entry.
import { base64Decode, bytesEqual } from '../encoding.js';
import type { EcPublicJwk, Hasher, RandomSource, Signer, Verifier } from '../interfaces.js';
import { normalizeEcPublicJwk } from '../jwk.js';
import { parseCertificate, publicJwkFromPkcs8 } from '../x509/parse.js';

const KEY_ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;
const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

/** Accepts low-S and high-S signatures (WebCrypto does not normalise S). Never throws. */
export const webCryptoVerifier: Verifier = {
  async verify(publicJwk, data, signature) {
    try {
      const jwk = normalizeEcPublicJwk(publicJwk);
      if (!jwk || !(data instanceof Uint8Array) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
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

/** x5c must hold 1 or 2 certificates that all parse and, when 2, chain by name. Returns the leaf key. */
function x5cLeafKey(x5c: unknown): EcPublicJwk {
  if (!Array.isArray(x5c) || x5c.length < 1 || x5c.length > 2 || !x5c.every((c) => typeof c === 'string')) {
    throw new TypeError('x5c must hold one or two base64 certificates');
  }
  const certs = (x5c as string[]).map((c) => parseCertificate(base64Decode(c)));
  if (certs.length === 2 && !bytesEqual(certs[0]!.issuerName, certs[1]!.subjectName)) throw new TypeError('x5c[0] is not issued by x5c[1]');
  const key = certs[0]!.publicJwk;
  if (!key) throw new TypeError('x5c[0] does not hold an EC P-256 key');
  return key;
}

/**
 * ES256 Signer from a PKCS#8 private key (PEM string or DER bytes, imported non-extractable) or
 * an ECDSA P-256 private CryptoKey (which may be non-extractable). The public key is taken from
 * `x5c[0]` when given, else from `publicJwk`, else (PKCS#8 only) from the public key carried in
 * the PKCS#8 structure; the private key is never exported. A throwaway signature proves that the
 * public key belongs to the private key.
 */
export async function createWebCryptoSigner(options: {
  privateKey: CryptoKey | string | Uint8Array;
  publicJwk?: EcPublicJwk;
  x5c?: string[];
}): Promise<Signer> {
  const { privateKey, x5c } = options;
  let key: CryptoKey;
  let embedded: EcPublicJwk | null = null;
  if (typeof privateKey === 'string' || privateKey instanceof Uint8Array) {
    const pkcs8 = typeof privateKey === 'string' ? pemToPkcs8(privateKey) : privateKey;
    key = await subtle().importKey('pkcs8', pkcs8, KEY_ALG, false, ['sign']);
    embedded = publicJwkFromPkcs8(pkcs8);
  } else {
    const alg = privateKey?.algorithm as EcKeyAlgorithm | undefined;
    if (privateKey?.type !== 'private' || alg?.name !== 'ECDSA' || alg.namedCurve !== 'P-256' || !privateKey.usages.includes('sign')) {
      throw new TypeError('privateKey must be an ECDSA P-256 private key usable for signing');
    }
    key = privateKey;
  }
  const given = options.publicJwk === undefined ? null : normalizeEcPublicJwk(options.publicJwk);
  if (options.publicJwk !== undefined && !given) throw new TypeError('publicJwk must be an EC P-256 public JWK');
  const fromX5c = x5c === undefined ? null : x5cLeafKey(x5c);
  const publicJwk = fromX5c ?? given ?? embedded;
  if (!publicJwk) throw new TypeError('the public key is unknown: pass x5c or publicJwk');
  if (fromX5c && given && (fromX5c.x !== given.x || fromX5c.y !== given.y)) throw new TypeError('publicJwk differs from the x5c[0] key');

  const sign = async (data: Uint8Array) => new Uint8Array(await subtle().sign(SIGN_ALG, key, data));
  const probe = webCryptoRandom.bytes(32);
  if (!(await webCryptoVerifier.verify(publicJwk, probe, await sign(probe)))) {
    throw new TypeError('the public key does not belong to privateKey');
  }
  const signer: Signer = { alg: 'ES256', publicJwk, sign };
  if (x5c !== undefined) signer.x5c = [...x5c];
  return signer;
}

/** Fresh P-256 key pair; the private key is not extractable. */
export async function generateWebCryptoKeyPair(): Promise<{ privateKey: CryptoKey; publicJwk: EcPublicJwk }> {
  const pair = await subtle().generateKey(KEY_ALG, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle().exportKey('jwk', pair.publicKey);
  const publicJwk = normalizeEcPublicJwk({ kty, crv, x, y });
  if (!publicJwk) throw new TypeError('generated key is not EC P-256');
  return { privateKey: pair.privateKey, publicJwk };
}
