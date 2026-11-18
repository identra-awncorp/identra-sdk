// Encrypted credential vault (ADR-0009 sections 2, 3 and 5).
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { base64UrlDecode, base64UrlEncode, type Clock } from '@identra/sdk-core';
import {
  createCredentialVault,
  createInMemoryCredentialRepository,
  createInMemorySecretStorage,
  createSoftwareKeyStore,
  CredentialVaultError,
  CREDENTIALS_TABLE_DDL,
  DATA_KEY_NAME,
  type CredentialRow,
  type SecretStorage,
} from '@identra/sdk-app';
import { countingRandom } from './helpers/random.js';

const NOW = new Date('2026-11-19T08:00:00.000Z');
const clock: Clock = { now: () => new Date(NOW) };
const VCT = 'https://identra.awncorp.vn/vct/bang-tot-nghiep/v1';
const ISSUER = 'https://api-identra.awncorp.vn/issuers/truong-mau';
const compactOf = (i: number) => `eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJ4In0.c2lnbmF0dXJl${i}~WyJzYWx0IiwiaG9fdGVuIiwiTmd1eeG7hW4gVsSDbiBBIl0~`;

function setup() {
  const rows = new Map<string, CredentialRow>();
  const secretsMap = new Map<string, string>();
  const secrets = createInMemorySecretStorage(secretsMap);
  const random = countingRandom();
  const repository = createInMemoryCredentialRepository(rows);
  const vault = createCredentialVault({ repository, secrets, random, clock });
  return { rows, secretsMap, secrets, random, repository, vault };
}
const code = (c: CredentialVaultError['code']) => (e: unknown) => e instanceof CredentialVaultError && e.code === c;

describe('createCredentialVault', () => {
  test('save -> list -> open round trip; the row has exactly the ADR-0009 columns', async () => {
    const { vault, rows, secretsMap } = setup();
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'key-1' });
    assert.match(id, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(await vault.open(id), compactOf(1));
    const row = rows.get(id)!;
    assert.deepEqual(Object.keys(row).sort(), ['ciphertext', 'created_at', 'id', 'issuer', 'key_id', 'status_cache', 'status_checked_at', 'vct']);
    assert.deepEqual({ ...row, ciphertext: undefined }, { id, vct: VCT, issuer: ISSUER, key_id: 'key-1', ciphertext: undefined, status_cache: null, status_checked_at: null, created_at: NOW.toISOString() });
    const sealed = base64UrlDecode(row.ciphertext);
    assert.equal(sealed[0], 0x01);
    assert.equal(sealed.length, 1 + 12 + new TextEncoder().encode(compactOf(1)).length + 16);
    assert.deepEqual(await vault.list(), [{ id, vct: VCT, issuer: ISSUER, key_id: 'key-1', status_cache: null, status_checked_at: null, created_at: NOW.toISOString() }]);
    // One fixed secret item: the 32-byte data key.
    assert.deepEqual([...secretsMap.keys()], [DATA_KEY_NAME]);
    assert.equal(base64UrlDecode(secretsMap.get(DATA_KEY_NAME)!).length, 32);
  });

  test('the repository never sees plaintext', async () => {
    const { vault, rows } = setup();
    for (let i = 0; i < 5; i++) await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: `k${i}` });
    const stored = JSON.stringify([...rows.values()]);
    for (let i = 0; i < 5; i++) {
      assert.equal(stored.includes(compactOf(i)), false);
      for (const piece of compactOf(i).split(/[.~]/)) if (piece.length > 8) assert.equal(stored.includes(piece), false, piece);
    }
  });

  test('a fresh nonce from the RandomSource for each of 1000 saves', async () => {
    const { vault, rows, random } = setup();
    for (let i = 0; i < 1000; i++) await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: 'k' });
    const nonces = new Set([...rows.values()].map((r) => base64UrlEncode(base64UrlDecode(r.ciphertext).subarray(1, 13))));
    assert.equal(nonces.size, 1000);
    // data key (32) once, then id (16) and nonce (12) per save
    assert.deepEqual(random.calls, [16, 32, 12, ...Array(999).fill([16, 12]).flat()]);
  });

  test('AAD binds the ciphertext to id, vct, issuer and key_id', async () => {
    const { vault, rows } = setup();
    const a = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'key-a' });
    const b = await vault.save({ compact: compactOf(2), vct: VCT, issuer: ISSUER, keyId: 'key-b' });
    const rowA = rows.get(a)!;
    const rowB = rows.get(b)!;
    // Ciphertext moved to another row.
    rows.set(b, { ...rowB, ciphertext: rowA.ciphertext });
    await assert.rejects(vault.open(b), code('UNDECRYPTABLE'));
    rows.set(b, rowB);
    for (const patch of [{ vct: VCT + 'x' }, { issuer: 'https://evil.example' }, { key_id: 'key-b' }]) {
      rows.set(a, { ...rowA, ...patch });
      await assert.rejects(vault.open(a), code('UNDECRYPTABLE'), JSON.stringify(patch));
    }
    rows.set(a, rowA);
    assert.equal(await vault.open(a), compactOf(1));
    assert.equal(await vault.open(b), compactOf(2));
  });

  test('a one-bit flip anywhere in the sealed value fails to open', async () => {
    const { vault, rows } = setup();
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    const row = rows.get(id)!;
    const sealed = base64UrlDecode(row.ciphertext);
    for (const i of [0, 1, 12, 13, 40, sealed.length - 1]) {
      const bad = sealed.slice();
      bad[i]! ^= 0x01;
      rows.set(id, { ...row, ciphertext: base64UrlEncode(bad) });
      await assert.rejects(vault.open(id), code('UNDECRYPTABLE'), `byte ${i}`);
    }
    for (const bad of ['', 'AQ', '!!!', base64UrlEncode(sealed.subarray(0, 28))]) {
      rows.set(id, { ...row, ciphertext: bad });
      await assert.rejects(vault.open(id), code('UNDECRYPTABLE'));
    }
  });

  test('errors carry no plaintext or key material', async () => {
    const { vault, rows, secretsMap } = setup();
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    rows.set(id, { ...rows.get(id)!, key_id: 'other' });
    const err = (await vault.open(id).then(
      () => assert.fail('opened'),
      (e: unknown) => e,
    )) as Error;
    const text = `${err.message} ${err.stack} ${JSON.stringify(err)}`;
    assert.equal(text.includes(compactOf(1)), false);
    assert.equal(text.includes(secretsMap.get(DATA_KEY_NAME)!), false);
    assert.equal(err.cause, undefined);
  });

  test('list() reads no secret, so it cannot decrypt', async () => {
    const map = new Map<string, string>();
    const inner = createInMemorySecretStorage(map);
    let gets = 0;
    const spied: SecretStorage = { ...inner, get: (k) => (gets++, inner.get(k)) };
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(), secrets: spied, random: countingRandom(), clock });
    await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    gets = 0;
    const listed = await vault.list();
    assert.equal(gets, 0);
    assert.equal(listed.length, 1);
    assert.equal('ciphertext' in listed[0]!, false);
  });

  test('purgeUndecryptable after the data key is replaced deletes every row', async () => {
    const { vault, rows, secretsMap } = setup();
    for (let i = 0; i < 4; i++) await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: `k${i}` });
    // A new phone restored from backup: the rows came along, the data key did not.
    secretsMap.delete(DATA_KEY_NAME);
    assert.equal(await vault.purgeUndecryptable(), 4);
    assert.equal(rows.size, 0);
    // The vault keeps working under the new key.
    const id = await vault.save({ compact: compactOf(9), vct: VCT, issuer: ISSUER, keyId: 'k9' });
    assert.equal(await vault.open(id), compactOf(9));
    assert.equal(await vault.purgeUndecryptable(), 0);
  });

  test('purgeUndecryptable after partial corruption deletes exactly the corrupt rows', async () => {
    const { vault, rows } = setup();
    const ids: string[] = [];
    for (let i = 0; i < 6; i++) ids.push(await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: `k${i}` }));
    for (const i of [1, 4]) {
      const row = rows.get(ids[i]!)!;
      const sealed = base64UrlDecode(row.ciphertext);
      sealed[20]! ^= 0x80;
      rows.set(row.id, { ...row, ciphertext: base64UrlEncode(sealed) });
    }
    assert.equal(await vault.purgeUndecryptable(), 2);
    assert.deepEqual([...rows.keys()].sort(), [ids[0], ids[2], ids[3], ids[5]].sort());
    for (const i of [0, 2, 3, 5]) assert.equal(await vault.open(ids[i]!), compactOf(i));
  });

  test('a corrupt stored data key is an error, never a silent purge', async () => {
    const { vault, rows, secretsMap } = setup();
    await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    secretsMap.set(DATA_KEY_NAME, 'short');
    await assert.rejects(vault.purgeUndecryptable(), code('DATA_KEY_INVALID'));
    assert.equal(rows.size, 1);
  });

  test('concurrent first saves share one data key', async () => {
    const { vault } = setup();
    const ids = await Promise.all(Array.from({ length: 5 }, (_, i) => vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: 'k' })));
    for (let i = 0; i < 5; i++) assert.equal(await vault.open(ids[i]!), compactOf(i));
  });

  test('setStatus updates the status columns only', async () => {
    const { vault, rows } = setup();
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    const before = rows.get(id)!;
    const checkedAt = new Date('2026-11-19T09:30:00.000Z');
    await vault.setStatus(id, 'revoked', checkedAt);
    assert.deepEqual(rows.get(id), { ...before, status_cache: 'revoked', status_checked_at: '2026-11-19T09:30:00.000Z' });
    assert.equal(await vault.open(id), compactOf(1));
    await assert.rejects(vault.setStatus('missing', 'valid', checkedAt), code('NOT_FOUND'));
    await assert.rejects(vault.setStatus(id, 'bogus' as 'valid', checkedAt), TypeError);
    await assert.rejects(vault.setStatus(id, 'valid', new Date(NaN)), TypeError);
  });

  test('open of an unknown id, remove, and removeWithKey', async () => {
    const { vault, rows, random } = setup();
    await assert.rejects(vault.open('missing'), code('NOT_FOUND'));
    const keySecrets = new Map<string, string>();
    const keyStore = createSoftwareKeyStore({ secrets: createInMemorySecretStorage(keySecrets), random });
    const { keyId } = await keyStore.create();
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId });
    const other = await vault.save({ compact: compactOf(2), vct: VCT, issuer: ISSUER, keyId: 'k2' });
    await vault.removeWithKey(id, keyStore);
    await vault.removeWithKey(id, keyStore);
    assert.equal(rows.has(id), false);
    assert.equal(keySecrets.size, 0);
    await vault.remove(other);
    await vault.remove(other);
    assert.equal(rows.size, 0);
  });

  test('save refuses empty fields', async () => {
    const { vault } = setup();
    for (const bad of [{ compact: '' }, { vct: '' }, { issuer: '' }, { keyId: '' }]) {
      await assert.rejects(vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k', ...bad }), TypeError);
    }
  });

  test('the DDL defines exactly the row columns', () => {
    const columns = [...CREDENTIALS_TABLE_DDL.matchAll(/^\s+([a-z_]+) [A-Z]+/gm)].map((m) => m[1]);
    assert.deepEqual(columns, ['id', 'vct', 'issuer', 'key_id', 'ciphertext', 'status_cache', 'status_checked_at', 'created_at']);
  });
});
