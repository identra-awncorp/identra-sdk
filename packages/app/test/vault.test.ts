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
  RandomSourceError,
  type CredentialRow,
  type SecretStorage,
} from '@identra/sdk-app';
import { constantRandom, countingRandom } from './helpers/random.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

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
    assert.equal(sealed[0], 0x02);
    // version, 8-byte key-check value = HMAC-SHA256(dataKey, "identra.vault.kcv")[0..8], nonce, ciphertext, tag
    assert.deepEqual(sealed.subarray(1, 9), hmac(sha256, base64UrlDecode(secretsMap.get(DATA_KEY_NAME)!), new TextEncoder().encode('identra.vault.kcv')).subarray(0, 8));
    assert.equal(sealed.length, 1 + 8 + 12 + new TextEncoder().encode(compactOf(1)).length + 16);
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
    const nonces = new Set([...rows.values()].map((r) => base64UrlEncode(base64UrlDecode(r.ciphertext).subarray(9, 21))));
    assert.equal(nonces.size, 1000);
    // data key (32) once, then id (16) and nonce (12) per save
    assert.deepEqual(random.calls, [32, 16, 12, ...Array(999).fill([16, 12]).flat()]);
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

  test('AAD field boundaries: vct "a" + issuer "bc" is not vct "ab" + issuer "c"', async () => {
    const { vault, rows } = setup();
    const id = await vault.save({ compact: compactOf(1), vct: 'a', issuer: 'bc', keyId: 'k' });
    const row = rows.get(id)!;
    for (const patch of [{ vct: 'ab', issuer: 'c' }, { vct: 'a","bc', issuer: '' }, { vct: 'abc', issuer: '' }]) {
      rows.set(id, { ...row, ...patch });
      await assert.rejects(vault.open(id), code('UNDECRYPTABLE'), JSON.stringify(patch));
    }
    rows.set(id, row);
    assert.equal(await vault.open(id), compactOf(1));
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

  test('purgeUndecryptable deletes exactly the rows sealed under another data key', async () => {
    const { vault, rows, secretsMap } = setup();
    const ours: string[] = [];
    for (let i = 0; i < 3; i++) ours.push(await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: `k${i}` }));
    // Rows sealed by another vault (another data key), e.g. copied in from an older install.
    const foreign = setup();
    for (let i = 0; i < 2; i++) {
      const id = await foreign.vault.save({ compact: compactOf(10 + i), vct: VCT, issuer: ISSUER, keyId: `f${i}` });
      rows.set(id, foreign.rows.get(id)!);
    }
    const before = secretsMap.get(DATA_KEY_NAME);
    assert.deepEqual(await vault.purgeUndecryptable(), { deleted: 2, kept: [] });
    assert.deepEqual([...rows.keys()].sort(), [...ours].sort());
    assert.equal(secretsMap.get(DATA_KEY_NAME), before);
    // With the data key itself replaced, every row is someone else's.
    secretsMap.set(DATA_KEY_NAME, base64UrlEncode(new Uint8Array(32).map((_, i) => i)));
    assert.deepEqual(await vault.purgeUndecryptable(), { deleted: 3, kept: [] });
    assert.equal(rows.size, 0);
  });

  test('purgeUndecryptable keeps and reports rows that fail under the CURRENT key (reviewer e4 section 3)', async () => {
    const { vault, rows } = setup();
    const ids: string[] = [];
    for (let i = 0; i < 8; i++) ids.push(await vault.save({ compact: compactOf(i), vct: i === 0 ? 'Bằng tốt nghiệp'.normalize('NFC') : VCT, issuer: ISSUER, keyId: `k${i}` }));
    const row = (i: number) => rows.get(ids[i]!)!;
    const sealedOf = (i: number) => base64UrlDecode(row(i).ciphertext);
    const withByte = (i: number, at: number, value: number) => {
      const b = sealedOf(i);
      b[at] = value;
      return base64UrlEncode(b);
    };
    rows.set(ids[0]!, { ...row(0), vct: row(0).vct.normalize('NFD') }); // a text-normalising layer
    rows.set(ids[1]!, { ...row(1), ciphertext: null as unknown as string }); // a bad read
    rows.set(ids[2]!, { ...row(2), key_id: 'k2-migrated' }); // a migration
    rows.set(ids[3]!, { ...row(3), ciphertext: withByte(3, 0, 0x01) }); // old version byte
    rows.set(ids[4]!, { ...row(4), ciphertext: withByte(4, 0, 0xff) }); // unknown version byte
    rows.set(ids[5]!, { ...row(5), ciphertext: withByte(5, 30, sealedOf(5)[30]! ^ 0x80) }); // corrupted ciphertext
    rows.set(ids[6]!, { ...row(6), ciphertext: base64UrlEncode(sealedOf(6).subarray(0, 20)) }); // truncated
    const result = await vault.purgeUndecryptable();
    assert.equal(result.deleted, 0);
    assert.deepEqual(
      result.kept.sort((a, b) => (a.id < b.id ? -1 : 1)),
      [
        { id: ids[0]!, reason: 'CORRUPT' },
        { id: ids[1]!, reason: 'UNKNOWN_FORMAT' },
        { id: ids[2]!, reason: 'CORRUPT' },
        { id: ids[3]!, reason: 'UNKNOWN_FORMAT' },
        { id: ids[4]!, reason: 'UNKNOWN_FORMAT' },
        { id: ids[5]!, reason: 'CORRUPT' },
        { id: ids[6]!, reason: 'UNKNOWN_FORMAT' },
      ].sort((a, b) => (a.id < b.id ? -1 : 1)),
    );
    assert.equal(rows.size, 8);
    assert.equal(await vault.open(ids[7]!), compactOf(7));
  });

  test('a missing data key: open, purge, list and setStatus never write one; save refuses while rows exist', async () => {
    const { rows, secretsMap } = setup();
    const inner = createInMemorySecretStorage(secretsMap);
    let writes = 0;
    const secrets: SecretStorage = { ...inner, set: (k, v) => (writes++, inner.set(k, v)) };
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(rows), secrets, random: countingRandom(), clock });
    const id = await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    assert.equal(writes, 1);
    secretsMap.delete(DATA_KEY_NAME);
    await assert.rejects(vault.open(id), code('DATA_KEY_MISSING'));
    await assert.rejects(vault.purgeUndecryptable(), code('DATA_KEY_MISSING'));
    await vault.list();
    await vault.setStatus(id, 'valid', NOW);
    await assert.rejects(vault.save({ compact: compactOf(2), vct: VCT, issuer: ISSUER, keyId: 'k' }), code('DATA_KEY_MISSING'));
    assert.equal(writes, 1);
    assert.equal(secretsMap.has(DATA_KEY_NAME), false);
    assert.equal(rows.size, 1);
  });

  test('a spurious null from SecretStorage.get does not overwrite the key (reviewer e4 sections 1 and 6)', async () => {
    const { rows, secretsMap } = setup();
    const inner = createInMemorySecretStorage(secretsMap);
    let locked = false;
    const secrets: SecretStorage = { ...inner, get: async (k) => (locked && k === DATA_KEY_NAME ? null : inner.get(k)) };
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(rows), secrets, random: countingRandom(), clock });
    const ids = [await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' }), await vault.save({ compact: compactOf(2), vct: VCT, issuer: ISSUER, keyId: 'k' })];
    const key = secretsMap.get(DATA_KEY_NAME);
    locked = true;
    await assert.rejects(vault.open(ids[0]!), code('DATA_KEY_MISSING'));
    await assert.rejects(vault.purgeUndecryptable(), code('DATA_KEY_MISSING'));
    await assert.rejects(vault.save({ compact: compactOf(3), vct: VCT, issuer: ISSUER, keyId: 'k' }), code('DATA_KEY_MISSING'));
    locked = false;
    assert.equal(secretsMap.get(DATA_KEY_NAME), key);
    assert.equal(await vault.open(ids[0]!), compactOf(1));
    assert.deepEqual(await vault.purgeUndecryptable(), { deleted: 0, kept: [] });
  });

  test('resetForNewDevice deletes every row and the data key; the next save starts afresh', async () => {
    const { vault, rows, secretsMap } = setup();
    for (let i = 0; i < 3; i++) await vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: `k${i}` });
    // A restored phone: rows came along, the data key did not.
    secretsMap.delete(DATA_KEY_NAME);
    await vault.resetForNewDevice();
    assert.equal(rows.size, 0);
    assert.equal(secretsMap.has(DATA_KEY_NAME), false);
    const id = await vault.save({ compact: compactOf(9), vct: VCT, issuer: ISSUER, keyId: 'k9' });
    assert.equal(await vault.open(id), compactOf(9));
  });

  test('a corrupt stored data key is an error, never a silent purge', async () => {
    const { vault, rows, secretsMap } = setup();
    await vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' });
    for (const bad of ['short', base64UrlEncode(new Uint8Array(31)), '!!!']) {
      secretsMap.set(DATA_KEY_NAME, bad);
      await assert.rejects(vault.purgeUndecryptable(), code('DATA_KEY_INVALID'));
      await assert.rejects(vault.save({ compact: compactOf(2), vct: VCT, issuer: ISSUER, keyId: 'k' }), code('DATA_KEY_INVALID'));
      assert.equal(secretsMap.get(DATA_KEY_NAME), bad);
    }
    assert.equal(rows.size, 1);
  });

  test('concurrent first saves share one data key, within one vault', async () => {
    const { vault } = setup();
    const ids = await Promise.all(Array.from({ length: 5 }, (_, i) => vault.save({ compact: compactOf(i), vct: VCT, issuer: ISSUER, keyId: 'k' })));
    for (let i = 0; i < 5; i++) assert.equal(await vault.open(ids[i]!), compactOf(i));
  });

  test('two vaults on one async, jittered storage racing the first save never lose a row (reviewer e4 section 2)', async () => {
    const jitter = () => new Promise((r) => setTimeout(r, Math.random() * 4));
    let lost = 0;
    for (let t = 0; t < 60; t++) {
      const inner = createInMemorySecretStorage();
      const secrets: SecretStorage = {
        get: async (k) => (await jitter(), inner.get(k)),
        set: async (k, v) => (await jitter(), inner.set(k, v)),
        delete: inner.delete,
      };
      const repository = createInMemoryCredentialRepository();
      const v1 = createCredentialVault({ repository, secrets, random: countingRandom(), clock });
      const v2 = createCredentialVault({ repository, secrets, random: countingRandom(), clock });
      const [a, b] = await Promise.all([
        v1.save({ compact: 'A', vct: VCT, issuer: ISSUER, keyId: 'k' }),
        v2.save({ compact: 'B', vct: VCT, issuer: ISSUER, keyId: 'k' }),
      ]);
      if ((await v1.open(a).catch(() => null)) !== 'A' || (await v2.open(b).catch(() => null)) !== 'B') lost++;
    }
    assert.equal(lost, 0);
  });

  test('a broken RandomSource is refused before anything is written', async () => {
    const rows = new Map<string, CredentialRow>();
    const secretsMap = new Map<string, string>();
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(rows), secrets: createInMemorySecretStorage(secretsMap), random: constantRandom(0), clock });
    await assert.rejects(vault.save({ compact: compactOf(1), vct: VCT, issuer: ISSUER, keyId: 'k' }), RandomSourceError);
    assert.equal(secretsMap.size + rows.size, 0);
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

describe('metadata without decryption', () => {
  test('dataKeyState never writes; getMeta reads one row without the data key', async () => {
    const map = new Map<string, string>();
    const writes: string[] = [];
    const inner = createInMemorySecretStorage(map);
    const secrets: SecretStorage = { ...inner, set: (k, v) => (writes.push(k), inner.set(k, v)) };
    const rows = new Map<string, CredentialRow>();
    const vault = createCredentialVault({ repository: createInMemoryCredentialRepository(rows), secrets, random: countingRandom(), clock: { now: () => new Date('2026-06-01T00:00:00Z') } });
    assert.equal(await vault.dataKeyState(), 'missing');
    assert.deepEqual(writes, []);
    const id = await vault.save({ compact: 'a.b.c~', vct: 'https://v.example', issuer: 'https://i.example', keyId: 'k1' });
    assert.equal(await vault.dataKeyState(), 'present');
    map.delete(DATA_KEY_NAME);
    const meta = await vault.getMeta(id);
    assert.deepEqual(meta, { id, vct: 'https://v.example', issuer: 'https://i.example', key_id: 'k1', status_cache: null, status_checked_at: null, created_at: '2026-06-01T00:00:00.000Z' });
    assert.equal('ciphertext' in meta!, false);
    assert.equal(await vault.getMeta('missing'), null);
    assert.equal(await vault.dataKeyState(), 'missing');
  });
});
