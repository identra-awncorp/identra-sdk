// Software WalletKeyStore (ADR-0009 sections 1 and 2).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64UrlDecode, utf8Encode } from '@identra/sdk-core';
import { webCryptoVerifier } from '@identra/sdk-core/webcrypto';
import { createInMemorySecretStorage, createNobleSigner, createSoftwareKeyStore, nobleVerifier, WalletKeyError, type SecretStorage } from '@identra/sdk-app';
import { countingRandom } from './helpers/random.js';

function setup() {
  const map = new Map<string, string>();
  const random = countingRandom();
  return { map, random, store: createSoftwareKeyStore({ secrets: createInMemorySecretStorage(map), random }) };
}
const notFound = (e: unknown) => e instanceof WalletKeyError && e.code === 'KEY_NOT_FOUND';

describe('createSoftwareKeyStore', () => {
  test('create -> signer -> the signature verifies with the returned public JWK', async () => {
    const { store } = setup();
    const { keyId, publicJwk } = await store.create();
    const signer = await store.signer(keyId);
    assert.deepEqual(signer.publicJwk, publicJwk);
    assert.equal('x5c' in signer, false);
    const data = utf8Encode('kb-jwt signing input');
    const sig = await signer.sign(data);
    assert.equal(await nobleVerifier.verify(publicJwk, data, sig), true);
    assert.equal(await webCryptoVerifier.verify(publicJwk, data, sig), true);
  });

  test('one key per call: distinct ids and keys; only the injected RandomSource is used', async () => {
    const { store, random } = setup();
    const created = [];
    for (let i = 0; i < 10; i++) created.push(await store.create());
    assert.equal(new Set(created.map((c) => c.keyId)).size, 10);
    assert.equal(new Set(created.map((c) => c.publicJwk.x)).size, 10);
    assert.deepEqual(random.calls, Array(10).fill([16, 48]).flat());
    for (const c of created) assert.match(c.keyId, /^[A-Za-z0-9_-]{22}$/);
  });

  test('secrets go only through SecretStorage: one item per key, a 43-character base64url scalar', async () => {
    const { store, map } = setup();
    const ids = [(await store.create()).keyId, (await store.create()).keyId];
    assert.deepEqual([...map.keys()].sort(), ids.map((id) => `identra.key.${id}`).sort());
    for (const [name, value] of map) {
      assert.match(value, /^[A-Za-z0-9_-]{43}$/);
      const scalar = base64UrlDecode(value);
      assert.equal(scalar.length, 32);
      // The stored scalar is the key behind the signer.
      const id = name.slice('identra.key.'.length);
      assert.deepEqual(createNobleSigner(scalar).publicJwk, (await store.signer(id)).publicJwk);
    }
  });

  test('an unknown or malformed id rejects with KEY_NOT_FOUND', async () => {
    const { store } = setup();
    await assert.rejects(store.signer('AAAAAAAAAAAAAAAAAAAAAA'), notFound);
    await assert.rejects(store.signer('../../etc'), notFound);
    await assert.rejects(store.signer(42 as unknown as string), notFound);
  });

  test('a corrupt stored value rejects with KEY_CORRUPT', async () => {
    const { store, map } = setup();
    const { keyId } = await store.create();
    for (const bad of ['', 'not base64!', 'A'.repeat(42), 'A'.repeat(43)]) {
      map.set(`identra.key.${keyId}`, bad);
      await assert.rejects(store.signer(keyId), (e: unknown) => e instanceof WalletKeyError && e.code === 'KEY_CORRUPT', bad);
    }
  });

  test('delete removes the secret and is idempotent', async () => {
    const { store, map } = setup();
    const a = await store.create();
    const b = await store.create();
    await store.delete(a.keyId);
    await store.delete(a.keyId);
    await store.delete('never-existed');
    await assert.rejects(store.signer(a.keyId), notFound);
    assert.deepEqual([...map.keys()], [`identra.key.${b.keyId}`]);
    await store.signer(b.keyId);
  });

  test('a storage failure propagates', async () => {
    const failing: SecretStorage = {
      get: async () => null,
      set: async () => {
        throw new Error('keychain unavailable');
      },
      delete: async () => {},
    };
    const store = createSoftwareKeyStore({ secrets: failing, random: countingRandom() });
    await assert.rejects(store.create(), /keychain unavailable/);
  });
});
