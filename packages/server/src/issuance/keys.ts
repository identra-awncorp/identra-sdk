// The two keys of an issuer that live only in memory: the ES256 key that signs access tokens and
// the ECDH P-256 key wallets encrypt credential requests to (OpenID4VCI 1.0 section 10). Generated
// at start, never exported. A restart invalidates outstanding access tokens (300 s) and the
// request-encryption key a wallet read from the metadata a moment before: both flows simply fail
// and the user scans a new offer.
import { base64UrlEncode, normalizeEcPublicJwk, type EcPublicJwk, type RandomSource, type Signer } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair } from '@identra/sdk-core/webcrypto';

export interface IssuerKeys {
  accessToken: { signer: Signer & { kid: string }; publicJwk: EcPublicJwk & { kid: string; alg: 'ES256'; use: 'sig' } };
  requestEncryption: { privateKey: CryptoKey; publicJwk: EcPublicJwk & { kid: string; alg: 'ECDH-ES'; use: 'enc' } };
}

/** Fresh keys; `kid`s are 128 random bits from `random`, the key material comes from WebCrypto. */
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
  };
}
