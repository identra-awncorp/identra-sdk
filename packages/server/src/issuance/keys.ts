// The keys of an issuer that live only in process memory: the ES256 key that signs access tokens,
// the ECDH P-256 key wallets encrypt credential requests to (OpenID4VCI 1.0 section 10), and the
// HMAC key of the PIN hashes (so the state store alone never lets anyone recover a PIN). Generated
// at start, never exported. A restart invalidates outstanding access tokens (300 s), the
// request-encryption key a wallet read from the metadata a moment before, and the PINs of pending
// offers (at most 10 minutes of offers): those flows fail and the user asks for a new offer.
import { base64UrlEncode, normalizeEcPublicJwk, type EcPublicJwk, type RandomSource, type Signer } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair } from '@identra/sdk-core/webcrypto';

export interface IssuerKeys {
  accessToken: { signer: Signer & { kid: string }; publicJwk: EcPublicJwk & { kid: string; alg: 'ES256'; use: 'sig' } };
  requestEncryption: { privateKey: CryptoKey; publicJwk: EcPublicJwk & { kid: string; alg: 'ECDH-ES'; use: 'enc' } };
  /** 256-bit HMAC-SHA-256 key of the PIN hashes. */
  pinKey: Uint8Array;
}

/** Fresh keys; `kid`s (128 bits) and the PIN key (256 bits) from `random`, the key pairs from WebCrypto. */
export async function generateIssuerKeys(random: RandomSource): Promise<IssuerKeys> {
  const kid = () => base64UrlEncode(random.bytes(16));
  const sig = await generateWebCryptoKeyPair();
  const signer = Object.assign(await createWebCryptoSigner({ privateKey: sig.privateKey, publicJwk: sig.publicJwk }), { kid: kid() });
  const ecdh = await globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const encPublic = normalizeEcPublicJwk(await globalThis.crypto.subtle.exportKey('jwk', ecdh.publicKey));
  if (!encPublic) throw new Error('generated ECDH key is not P-256');
  return {
    accessToken: { signer, publicJwk: { ...sig.publicJwk, kid: signer.kid, alg: 'ES256', use: 'sig' } },
    requestEncryption: { privateKey: ecdh.privateKey, publicJwk: { ...encPublic, kid: kid(), alg: 'ECDH-ES', use: 'enc' } },
    pinKey: random.bytes(32).slice(),
  };
}
