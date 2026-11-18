// Encrypted credential store (ADR-0009 sections 2, 3, 5). Each compact credential is sealed with
// AES-256-GCM under one 32-byte data key kept in SecretStorage; the rows live in a repository the
// app implements on expo-sqlite. The repository never sees plaintext.
import { gcm } from '@noble/ciphers/aes.js';
import { base64UrlDecode, base64UrlEncode, concatBytes, utf8Decode, utf8Encode } from '@identra/sdk-core';
import type { Clock, RandomSource } from '@identra/sdk-core';
import type { SecretStorage, WalletKeyStore } from './key-store.js';

export type CredentialStatus = 'valid' | 'revoked' | 'suspended' | 'unavailable';

/** One row of the `credentials` table, columns exactly as in ADR-0009 section 3. */
export interface CredentialRow {
  id: string;
  vct: string;
  issuer: string;
  key_id: string;
  /** base64url(version 0x01 || 12-byte nonce || AES-256-GCM ciphertext || 16-byte tag) */
  ciphertext: string;
  status_cache: CredentialStatus | null;
  /** ISO 8601 */
  status_checked_at: string | null;
  /** ISO 8601 */
  created_at: string;
}

/** The SQLite definition of the table, shared by the app and the docs. */
export const CREDENTIALS_TABLE_DDL = `CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY NOT NULL,
  vct TEXT NOT NULL,
  issuer TEXT NOT NULL,
  key_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  status_cache TEXT CHECK (status_cache IN ('valid', 'revoked', 'suspended', 'unavailable')),
  status_checked_at TEXT,
  created_at TEXT NOT NULL
)`;

export interface CredentialRepository {
  /** Rejects when a row with the same id exists. */
  insert(row: CredentialRow): Promise<void>;
  list(): Promise<CredentialRow[]>;
  get(id: string): Promise<CredentialRow | null>;
  update(id: string, patch: { status_cache: CredentialStatus | null; status_checked_at: string | null }): Promise<void>;
  /** Idempotent. */
  delete(id: string): Promise<void>;
}

/** In-memory CredentialRepository for Node and tests. Pass a Map to inspect the rows. */
export function createInMemoryCredentialRepository(map: Map<string, CredentialRow> = new Map()): CredentialRepository {
  return {
    async insert(row) {
      if (map.has(row.id)) throw new Error('duplicate credential id');
      map.set(row.id, { ...row });
    },
    async list() {
      return [...map.values()].map((r) => ({ ...r }));
    },
    async get(id) {
      const r = map.get(id);
      return r ? { ...r } : null;
    },
    async update(id, patch) {
      const r = map.get(id);
      if (r) map.set(id, { ...r, status_cache: patch.status_cache, status_checked_at: patch.status_checked_at });
    },
    async delete(id) {
      map.delete(id);
    },
  };
}

/** A row without its ciphertext: what list() returns. */
export type CredentialMetadata = Omit<CredentialRow, 'ciphertext'>;

export class CredentialVaultError extends Error {
  readonly code: 'NOT_FOUND' | 'UNDECRYPTABLE' | 'DATA_KEY_INVALID';
  constructor(code: 'NOT_FOUND' | 'UNDECRYPTABLE' | 'DATA_KEY_INVALID') {
    super({ NOT_FOUND: 'credential not found', UNDECRYPTABLE: 'credential cannot be decrypted', DATA_KEY_INVALID: 'stored data key is invalid' }[code]);
    this.name = 'CredentialVaultError';
    this.code = code;
  }
}

export interface CredentialVault {
  /** Encrypts and stores a compact credential; returns the new row id. */
  save(input: { compact: string; vct: string; issuer: string; keyId: string }): Promise<string>;
  /** Metadata of every row; never decrypts. */
  list(): Promise<CredentialMetadata[]>;
  /** The compact credential. Rejects with CredentialVaultError NOT_FOUND or UNDECRYPTABLE. */
  open(id: string): Promise<string>;
  /** Deletes the row only (idempotent); see removeWithKey. */
  remove(id: string): Promise<void>;
  /** Deletes the row, then its wallet key (idempotent). */
  removeWithKey(id: string, keyStore: WalletKeyStore): Promise<void>;
  /** Deletes every row that does not decrypt under the current data key; returns how many. */
  purgeUndecryptable(): Promise<number>;
  setStatus(id: string, status: CredentialStatus, checkedAt: Date): Promise<void>;
}

/** SecretStorage item holding base64url of the 32-byte data key. */
export const DATA_KEY_NAME = 'identra.vault.data-key';
const VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function randomBytes(random: RandomSource, n: number): Uint8Array {
  const b = random.bytes(n);
  if (!(b instanceof Uint8Array) || b.length !== n) throw new TypeError(`RandomSource must return ${n} bytes`);
  return b;
}

/** Binds a ciphertext to its row: moving it to another row or editing these columns breaks it. */
function associatedData(row: Pick<CredentialRow, 'id' | 'vct' | 'issuer' | 'key_id'>): Uint8Array {
  return utf8Encode(JSON.stringify(['identra.credential', VERSION, row.id, row.vct, row.issuer, row.key_id]));
}

function decryptRow(row: CredentialRow, dataKey: Uint8Array): string {
  try {
    const sealed = base64UrlDecode(row.ciphertext);
    if (sealed.length < 1 + NONCE_BYTES + TAG_BYTES || sealed[0] !== VERSION) throw new Error();
    const nonce = sealed.subarray(1, 1 + NONCE_BYTES);
    const plaintext = gcm(dataKey, nonce, associatedData(row)).decrypt(sealed.subarray(1 + NONCE_BYTES));
    try {
      return utf8Decode(plaintext);
    } finally {
      plaintext.fill(0);
    }
  } catch {
    throw new CredentialVaultError('UNDECRYPTABLE');
  }
}

function requireString(v: unknown, name: string): string {
  if (typeof v !== 'string' || v.length === 0) throw new TypeError(`${name} must be a non-empty string`);
  return v;
}

/**
 * The credential vault. The data key is generated from `random` on first use and stored under
 * DATA_KEY_NAME; it is read for each operation that needs it and the decoded copy is zeroed after
 * (best-effort: the stored base64url string and the decrypted compact string cannot be erased).
 * Errors carry a code only, never key material or plaintext.
 */
export function createCredentialVault(options: { repository: CredentialRepository; secrets: SecretStorage; random: RandomSource; clock: Clock }): CredentialVault {
  const { repository, secrets, random, clock } = options;
  let creating: Promise<void> | null = null;

  async function readDataKey(): Promise<Uint8Array | null> {
    const stored = await secrets.get(DATA_KEY_NAME);
    if (stored === null) return null;
    let key: Uint8Array;
    try {
      key = base64UrlDecode(stored);
    } catch {
      throw new CredentialVaultError('DATA_KEY_INVALID');
    }
    if (key.length !== 32) throw new CredentialVaultError('DATA_KEY_INVALID');
    return key;
  }

  async function dataKey(): Promise<Uint8Array> {
    const existing = await readDataKey();
    if (existing) return existing;
    // Single flight, so two concurrent first saves cannot each write a different key.
    creating ??= (async () => {
      if ((await secrets.get(DATA_KEY_NAME)) !== null) return;
      const fresh = randomBytes(random, 32);
      try {
        await secrets.set(DATA_KEY_NAME, base64UrlEncode(fresh));
      } finally {
        fresh.fill(0);
      }
    })().finally(() => {
      creating = null;
    });
    await creating;
    const created = await readDataKey();
    if (!created) throw new CredentialVaultError('DATA_KEY_INVALID');
    return created;
  }

  const vault: CredentialVault = {
    async save(input) {
      const compact = requireString(input.compact, 'compact');
      const meta = {
        id: base64UrlEncode(randomBytes(random, 16)),
        vct: requireString(input.vct, 'vct'),
        issuer: requireString(input.issuer, 'issuer'),
        key_id: requireString(input.keyId, 'keyId'),
      };
      const key = await dataKey();
      let sealed: Uint8Array;
      const plaintext = utf8Encode(compact);
      try {
        const nonce = randomBytes(random, NONCE_BYTES);
        sealed = concatBytes(Uint8Array.of(VERSION), nonce, gcm(key, nonce, associatedData(meta)).encrypt(plaintext));
      } finally {
        key.fill(0);
        plaintext.fill(0);
      }
      await repository.insert({
        ...meta,
        ciphertext: base64UrlEncode(sealed),
        status_cache: null,
        status_checked_at: null,
        created_at: clock.now().toISOString(),
      });
      return meta.id;
    },

    async list() {
      return (await repository.list()).map((r) => ({
        id: r.id,
        vct: r.vct,
        issuer: r.issuer,
        key_id: r.key_id,
        status_cache: r.status_cache,
        status_checked_at: r.status_checked_at,
        created_at: r.created_at,
      }));
    },

    async open(id) {
      const row = await repository.get(id);
      if (!row) throw new CredentialVaultError('NOT_FOUND');
      const key = await dataKey();
      try {
        return decryptRow(row, key);
      } finally {
        key.fill(0);
      }
    },

    async remove(id) {
      await repository.delete(id);
    },

    async removeWithKey(id, keyStore) {
      const row = await repository.get(id);
      if (!row) return;
      await repository.delete(id);
      await keyStore.delete(row.key_id);
    },

    async purgeUndecryptable() {
      const rows = await repository.list();
      if (rows.length === 0) return 0;
      const key = await dataKey();
      let purged = 0;
      try {
        for (const row of rows) {
          try {
            decryptRow(row, key);
          } catch {
            await repository.delete(row.id);
            purged++;
          }
        }
      } finally {
        key.fill(0);
      }
      return purged;
    },

    async setStatus(id, status, checkedAt) {
      if (!['valid', 'revoked', 'suspended', 'unavailable'].includes(status)) throw new TypeError('invalid status');
      if (!(checkedAt instanceof Date) || Number.isNaN(checkedAt.getTime())) throw new TypeError('checkedAt must be a valid Date');
      if (!(await repository.get(id))) throw new CredentialVaultError('NOT_FOUND');
      await repository.update(id, { status_cache: status, status_checked_at: checkedAt.toISOString() });
    },
  };
  return vault;
}
