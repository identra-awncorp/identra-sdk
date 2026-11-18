// @identra/sdk-core/webcrypto adapters.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { base64Decode, decodeJws, signJws, utf8Encode, verifyJws } from '@identra/sdk-core';
import { createWebCryptoSigner, generateWebCryptoKeyPair, webCryptoHasher, webCryptoRandom, webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { nobleVerifier } from './helpers/noble.js';
import { b64, ca, pemFile, x5c } from './helpers/pki.js';

const verifies = async (...a: Parameters<typeof verifyJws>) => (await verifyJws(...a)) === null;
const keyPem = pemFile('test/leaf/vc.key.pem');

test('a signer from a PKCS#8 PEM carries its x5c into the JWS header and verifies on both backends', async () => {
  const signer = await createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('vc') });
  const compact = await signJws({ typ: 'dc+sd-jwt' }, utf8Encode('{"iss":"x"}'), signer);
  const r = decodeJws(compact, 16_384);
  assert.ok(r.ok);
  assert.deepEqual(r.jws.header['x5c'], x5c('vc'));
  assert.equal(await verifies(r.jws, signer.publicJwk, webCryptoVerifier), true);
  assert.equal(await verifies(r.jws, signer.publicJwk, nobleVerifier), true);
});

test('the public key comes from x5c, publicJwk or the PKCS#8 structure, never from exporting the private key', async () => {
  const der = base64Decode(keyPem.replace(/-----[A-Z ]+-----|\s/g, ''));
  const fromDer = await createWebCryptoSigner({ privateKey: der });
  const fromPem = await createWebCryptoSigner({ privateKey: keyPem });
  const fromX5c = await createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('vc') });
  assert.deepEqual(fromDer.publicJwk, fromX5c.publicJwk);
  assert.deepEqual(fromPem.publicJwk, fromX5c.publicJwk);
  const pair = await generateWebCryptoKeyPair();
  assert.equal(pair.privateKey.extractable, false);
  const fromKey = await createWebCryptoSigner({ privateKey: pair.privateKey, publicJwk: pair.publicJwk });
  assert.deepEqual(fromKey.publicJwk, pair.publicJwk);
  const data = utf8Encode('data');
  assert.equal(await webCryptoVerifier.verify(pair.publicJwk, data, await fromKey.sign(data)), true);
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.privateKey }), /pass x5c or publicJwk/);
});

test('createWebCryptoSigner refuses a public key that does not belong to the private key', async () => {
  const other = await generateWebCryptoKeyPair();
  const pair = await generateWebCryptoKeyPair();
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.privateKey, publicJwk: other.publicJwk }), /does not belong/);
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem, publicJwk: other.publicJwk }), /does not belong/);
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('vc'), publicJwk: other.publicJwk }), /differs from the x5c/);
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem, x5c: x5c('status') }), /does not belong/);
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.privateKey, publicJwk: { ...other.publicJwk, crv: 'P-384' as 'P-256' } }), TypeError);
});

test('createWebCryptoSigner requires an x5c of 1 or 2 parseable certificates that chain by name', async () => {
  const [leafB64, issuingB64] = x5c('vc') as [string, string];
  assert.deepEqual((await createWebCryptoSigner({ privateKey: keyPem, x5c: [leafB64] })).x5c, [leafB64]);
  const bad: unknown[] = [[], [leafB64, 'not base64!'], [leafB64, b64(ca('root'))], [leafB64, issuingB64, b64(ca('root'))], [issuingB64, leafB64], [leafB64, 42]];
  for (const chain of bad) await assert.rejects(createWebCryptoSigner({ privateKey: keyPem, x5c: chain as string[] }), TypeError, JSON.stringify(chain).slice(0, 40));
});

test('createWebCryptoSigner refuses keys of the wrong kind', async () => {
  await assert.rejects(createWebCryptoSigner({ privateKey: keyPem.replace(/PRIVATE KEY/g, 'EC PRIVATE KEY') }), TypeError);
  await assert.rejects(createWebCryptoSigner({ privateKey: pemFile('test/leaf/p384.key.pem') }));
  await assert.rejects(createWebCryptoSigner({ privateKey: pemFile('test/leaf/rsa.key.pem') }));
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  await assert.rejects(createWebCryptoSigner({ privateKey: pair.publicKey }), TypeError, 'public key');
});

test('webCryptoVerifier returns false, never throws, on bad input', async () => {
  const { publicJwk } = await generateWebCryptoKeyPair();
  const data = utf8Encode('x');
  assert.equal(await webCryptoVerifier.verify(publicJwk, data, new Uint8Array(64)), false);
  assert.equal(await webCryptoVerifier.verify(publicJwk, data, new Uint8Array(70)), false);
  assert.equal(await webCryptoVerifier.verify({ ...publicJwk, x: publicJwk.y }, data, new Uint8Array(64)), false, 'point not on curve');
  assert.equal(await webCryptoVerifier.verify({ ...publicJwk, crv: 'P-384' as 'P-256' }, data, new Uint8Array(64)), false);
  const throwing = Object.defineProperty({ ...publicJwk }, 'kty', { get: () => { throw new Error('getter'); }, enumerable: true });
  for (const verifier of [webCryptoVerifier, nobleVerifier]) {
    assert.equal(await verifier.verify(throwing, data, new Uint8Array(64)), false, 'a throwing getter');
    assert.equal(await verifier.verify({ ...publicJwk, kty: 'OKP' as 'EC' }, data, new Uint8Array(64)), false);
  }
});

test('webCryptoHasher and webCryptoRandom', async () => {
  const data = new Uint8Array(randomBytes(100));
  assert.deepEqual(await webCryptoHasher.sha256(data), new Uint8Array(createHash('sha256').update(data).digest()));
  const a = webCryptoRandom.bytes(32);
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, webCryptoRandom.bytes(32));
});
