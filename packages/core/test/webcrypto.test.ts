// @identra/sdk-core/webcrypto adapters.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { base64Decode, decodeJws, signJws, utf8Encode, verifyJwsSignature } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleVerifier } from './helpers/noble.js';
import { pemFile, x5c } from './helpers/pki.js';

const keyPem = pemFile('test/leaf/vc.key.pem');

test('a signer from a PKCS#8 PEM carries its x5c into the JWS header and verifies on both backends', async () => {
  const signer = await createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('vc') });
  const compact = await signJws({ typ: 'dc+sd-jwt' }, utf8Encode('{"iss":"x"}'), signer);
  const r = decodeJws(compact);
  assert.ok(r.ok);
  assert.deepEqual(r.jws.header['x5c'], x5c('vc'));
  assert.equal(await verifyJwsSignature(r.jws, signer.publicJwk, webCryptoVerifier), true);
  assert.equal(await verifyJwsSignature(r.jws, signer.publicJwk, nobleVerifier), true);
});

test('a signer from PKCS#8 DER and from a generated CryptoKey', async () => {
  const der = base64Decode(keyPem.replace(/-----[A-Z ]+-----|\s/g, ''));
  const fromDer = await createWebCryptoSigner({ privateKey: der });
  const fromPem = await createWebCryptoSigner({ privateKey: keyPem });
  assert.deepEqual(fromDer.publicJwk, fromPem.publicJwk);
  const pair = await generateWebCryptoKeyPair();
  const fromKey = await createWebCryptoSigner({ privateKey: pair.privateKey });
  assert.deepEqual(fromKey.publicJwk, pair.publicJwk);
  const data = utf8Encode('data');
  assert.equal(await webCryptoVerifier.verify(pair.publicJwk, data, await fromKey.sign(data)), true);
});

test('createWebCryptoSigner refuses bad keys and an x5c for another key', async () => {
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('status') }), TypeError);
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem.replace(/PRIVATE KEY/g, 'EC PRIVATE KEY') }), TypeError);
  await assert.rejects(createWebCryptoSigner({ privateKey: pemFile('test/leaf/p384.key.pem') }));
  await assert.rejects(createWebCryptoSigner({ privateKey: pemFile('test/leaf/rsa.key.pem') }));
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.privateKey }), TypeError, 'non-extractable');
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.publicKey }), TypeError, 'public key');
});

test('webCryptoVerifier returns false, never throws, on bad input', async () => {
  const { publicJwk } = await generateWebCryptoKeyPair();
  const data = utf8Encode('x');
  assert.equal(await webCryptoVerifier.verify(publicJwk, data, new Uint8Array(64)), false);
  assert.equal(await webCryptoVerifier.verify(publicJwk, data, new Uint8Array(70)), false);
  assert.equal(await webCryptoVerifier.verify({ ...publicJwk, x: publicJwk.y }, data, new Uint8Array(64)), false, 'point not on curve');
  assert.equal(await webCryptoVerifier.verify({ ...publicJwk, crv: 'P-384' as 'P-256' }, data, new Uint8Array(64)), false);
});

test('webCryptoHasher and webCryptoRandom', async () => {
  const data = new Uint8Array(randomBytes(100));
  assert.deepEqual(await webCryptoHasher.sha256(data), new Uint8Array(createHash('sha256').update(data).digest()));
  const a = webCryptoRandom.bytes(32);
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, webCryptoRandom.bytes(32));
});
