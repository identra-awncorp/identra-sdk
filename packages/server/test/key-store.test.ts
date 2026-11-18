// createFileKeyStore against a freshly generated DEMO PKI: layout, refused names, file modes and
// key/certificate pairing.
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, cpSync, mkdtempSync, symlinkSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { base64Encode, decodeJws, signJws, utf8Encode, verifyJwsSignature } from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createFileKeyStore } from '@identra/sdk-server';
import { freshDemoPki, pemCerts } from './helpers.js';

const DEMO = freshDemoPki();
const store = createFileKeyStore(DEMO);
/** A writable copy of the demo PKI for the tests that break it. */
const copy = () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'identra-keystore-')), 'pki');
  cpSync(DEMO, dir, { recursive: true });
  return dir;
};

async function signsVerifiably(signer: Awaited<ReturnType<typeof store.signer>>) {
  const decoded = decodeJws(await signJws({ typ: 'test' }, utf8Encode('{}'), signer));
  assert.ok(decoded.ok);
  assert.equal(await verifyJwsSignature(decoded.jws, signer.publicJwk, webCryptoVerifier), true);
}

test('the demo layout: every organisation signer, the trust-list signer and the root', async () => {
  const cases: [string, 'vc' | 'status' | 'request', string][] = [
    ['truong-mau', 'vc', 'vc'], ['truong-mau', 'status', 'status'],
    ['nha-san-xuat', 'vc', 'vc-product'], ['kiem-dinh', 'status', 'status'], ['phan-phoi', 'vc', 'vc-product'],
    ['nha-tuyen-dung-mau', 'request', 'request'],
  ];
  for (const [org, purpose, file] of cases) {
    const signer = await store.signer(org, purpose);
    assert.deepEqual(signer.x5c, pemCerts(join(DEMO, 'orgs', org, `${file}.chain.pem`)).map(base64Encode), `${org}/${purpose}`);
    assert.equal(signer.alg, 'ES256');
    await signsVerifiably(signer);
  }
  const tl = await store.trustListSigner();
  assert.deepEqual(tl.x5c, pemCerts(join(DEMO, 'trust-list-signer/trust-list.cert.pem')).map(base64Encode));
  await signsVerifiably(tl);
  assert.deepEqual(store.trustedRoots(), pemCerts(join(DEMO, 'root.cert.pem')));
});

test('signers are cached, frozen and expose nothing but the Signer interface', async () => {
  const a = await store.signer('truong-mau', 'vc');
  assert.equal(await store.signer('truong-mau', 'vc'), a);
  assert.ok(Object.isFrozen(a));
  assert.deepEqual(Object.keys(a).sort(), ['alg', 'publicJwk', 'sign', 'x5c']);
  assert.doesNotMatch(JSON.stringify(a), /"d"|PRIVATE/);
});

test('names with path separators, dots or anything else are refused', async () => {
  for (const name of ['../truong-mau', 'truong-mau/../kiem-dinh', 'a/b', 'a\\b', '.', '..', 'truong.mau', '', 'Truong-mau', '-x', 'x-', 'a--b', 'a b']) {
    await assert.rejects(store.signer(name, 'vc'), TypeError, name);
  }
  for (const purpose of ['vc-product', 'trust-list', '../vc', 'constructor']) {
    await assert.rejects(store.signer('truong-mau', purpose as 'vc'), TypeError, purpose);
  }
  await assert.rejects(store.signer('khong-co', 'vc'), /expected exactly one vc or vc-product key for khong-co, found 0/);
});

test('a key file readable or writable by group or others is refused with a clear error', async () => {
  const dir = copy();
  const key = join(dir, 'orgs/truong-mau/vc.key.pem');
  for (const mode of [0o640, 0o604, 0o620, 0o602, 0o644]) {
    chmodSync(key, mode);
    await assert.rejects(createFileKeyStore(dir).signer('truong-mau', 'vc'), new RegExp(`accessible by group or others \\(mode ${mode.toString(8)}\\); run chmod 600`));
  }
  chmodSync(key, 0o400);
  await signsVerifiably(await createFileKeyStore(dir).signer('truong-mau', 'vc'));
  chmodSync(join(dir, 'trust-list-signer/trust-list.key.pem'), 0o644);
  await assert.rejects(createFileKeyStore(dir).trustListSigner(), /chmod 600/);
});

test('a failed load is not cached: fixing the file fixes the store', async () => {
  const dir = copy();
  const key = join(dir, 'orgs/truong-mau/status.key.pem');
  chmodSync(key, 0o644);
  const s = createFileKeyStore(dir);
  await assert.rejects(s.signer('truong-mau', 'status'), /chmod 600/);
  chmodSync(key, 0o600);
  await signsVerifiably(await s.signer('truong-mau', 'status'));
});

test('a key that does not belong to its certificate is refused', async () => {
  const dir = copy();
  const org = join(dir, 'orgs/truong-mau');
  copyFileSync(join(org, 'status.key.pem'), join(org, 'vc.key.pem'));
  await assert.rejects(createFileKeyStore(dir).signer('truong-mau', 'vc'), /does not match the public key of its certificate/);
  copyFileSync(join(dir, 'orgs/kiem-dinh/status.key.pem'), join(org, 'request.key.pem'));
  copyFileSync(join(dir, 'orgs/kiem-dinh/status.cert.pem'), join(org, 'request.chain.pem'));
  await assert.rejects(createFileKeyStore(dir).signer('truong-mau', 'request'), /must hold exactly 2 certificate/);
});

test('ambiguous or symlinked key files, extra roots', async () => {
  const dir = copy();
  const org = join(dir, 'orgs/nha-san-xuat');
  copyFileSync(join(org, 'vc-product.key.pem'), join(org, 'vc.key.pem'));
  await assert.rejects(createFileKeyStore(dir).signer('nha-san-xuat', 'vc'), /exactly one vc or vc-product key for nha-san-xuat, found 2/);
  unlinkSync(join(org, 'status.key.pem'));
  symlinkSync(join(org, 'vc-product.key.pem'), join(org, 'status.key.pem'));
  await assert.rejects(createFileKeyStore(dir).signer('nha-san-xuat', 'status'), /is not a regular file/);
  copyFileSync(join(dir, 'ca/issuing/ca.cert.pem'), join(dir, 'root2.cert.pem'));
  assert.equal(createFileKeyStore(dir).trustedRoots().length, 2);
});
