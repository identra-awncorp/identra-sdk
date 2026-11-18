// Issue with one crypto backend, verify with the other; high-S issuer signatures.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { p256 } from '@noble/curves/nist.js';
import {
  base64UrlDecode,
  createCertificateChainValidator,
  createPresentation,
  issueDiploma,
  type Hasher,
  type Signer,
  type Verifier,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleHasher, nobleSigner, nobleVerifier, P256_N } from './helpers/noble.js';
import { ca, NOW, pemFile, x5c } from './helpers/pki.js';
import { AUD, clock, codes, DIPLOMA, holderKey, ISS, issuerSigner, NONCE, presentationOptions, STATUS , verifyAny } from './helpers/sdjwt.js';

async function nobleIssuer(): Promise<Signer> {
  const der = Buffer.from(pemFile('test/leaf/vc.key.pem').replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const { d } = await crypto.subtle.exportKey('jwk', key);
  return { ...nobleSigner(base64UrlDecode(d!)), x5c: x5c('vc') };
}

async function roundTrip(issuer: Signer, holder: Signer, hasher: Hasher, verifier: Verifier) {
  const compact = await issueDiploma({ signer: issuer, hasher, random: webCryptoRandom, clock, iss: ISS, cnfJwk: holder.publicJwk, status: STATUS, claims: DIPLOMA });
  const presentation = await createPresentation({ compact, disclose: ['ho_ten'], holderSigner: holder, audience: AUD, nonce: NONCE, now: NOW, hasher });
  const chainValidator = createCertificateChainValidator({ trustedRoots: [ca('root')], verifier, hasher });
  return verifyAny(presentation, presentationOptions({ verifier, hasher, chainValidator }));
}

test('issue and present with noble, verify with WebCrypto, and the reverse', async () => {
  const nobleHolder = nobleSigner(p256.utils.randomSecretKey());
  const a = await roundTrip(await nobleIssuer(), nobleHolder, nobleHasher, webCryptoVerifier);
  assert.equal(a.ok, true, JSON.stringify(codes(a)));
  const b = await roundTrip(await issuerSigner(), await holderKey(), webCryptoHasher, nobleVerifier);
  assert.equal(b.ok, true, JSON.stringify(codes(b)));
  const c = await roundTrip(await nobleIssuer(), nobleHolder, nobleHasher, nobleVerifier);
  assert.equal(c.ok, true, JSON.stringify(codes(c)));
});

test('a high-S issuer signature verifies on both backends', async () => {
  const base = await issuerSigner();
  let highSignatures = 0;
  const highS: Signer = {
    ...base,
    async sign(data) {
      const sig = await base.sign(data);
      const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
      const high = s > P256_N / 2n ? s : P256_N - s;
      highSignatures++;
      return Uint8Array.from([...sig.subarray(0, 32), ...Buffer.from(high.toString(16).padStart(64, '0'), 'hex')]);
    },
  };
  for (const [verifier, hasher] of [[webCryptoVerifier, webCryptoHasher], [nobleVerifier, nobleHasher]] as const) {
    const r = await roundTrip(highS, await holderKey(), hasher, verifier);
    assert.equal(r.ok, true, JSON.stringify(codes(r)));
  }
  assert.equal(highSignatures, 2);
});
