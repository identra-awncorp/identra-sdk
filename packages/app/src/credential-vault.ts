// Encrypted credential store (ADR-0009 sections 2, 3, 5). Each compact credential is sealed with
// AES-256-GCM under one 32-byte data key kept in SecretStorage; the rows live in a repository the
// app implements on expo-sqlite. The repository never sees plaintext.
import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode, concatBytes, utf8Decode, utf8Encode } from '@identra/sdk-core';
import type { Clock, RandomSource } from '@identra/sdk-core';
import type { SecretStorage, WalletKeyStore } from './key-store.js';
import { drawRandom } from './random.js';

/**
 * The `status_cache` column. `unavailable`: only the status list or the trust list could not be
 * read (the wallet API calls it `unknown`); `invalid`: another check failed (issuer no longer
 * trusted, certificate expired, …).
 */
export type StoredCredentialStatus = 'valid' | 'revoked' | 'suspended' | 'unavailable' | 'invalid';

/** One row of the `credentials` table, columns exactly as in ADR-0009 section 3. */
export interface CredentialRow {
  id: string;
  vct: string;
  issuer: string;
  key_id: string;
  /** base64url(version 0x02 || 8-byte key-check value || 12-byte nonce || AES-256-GCM ciphertext || 16-byte tag) */
  ciphertext: string;
  status_cache: StoredCredentialStatus | null;
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
  status_cache TEXT CHECK (status_cache IN ('valid', 'revoked', 'suspended', 'unavailable', 'invalid')),
  status_checked_at TEXT,
  created_at TEXT NOT NULL
)`;

export interface CredentialRepository {
  /** Rejects when a row with the same id exists. */
  insert(row: CredentialRow): Promise<void>;
  list(): Promise<CredentialRow[]>;
  get(id: string): Promise<CredentialRow | null>;
  update(id: string, patch: { status_cache: StoredCredentialStatus | null; status_checked_at: string | null }): Promise<void>;
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

export type CredentialVaultErrorCode = 'NOT_FOUND' | 'UNDECRYPTABLE' | 'DATA_KEY_INVALID' | 'DATA_KEY_MISSING';

const MESSAGES: Record<CredentialVaultErrorCode, string> = {
  NOT_FOUND: 'credential not found',
  UNDECRYPTABLE: 'credential cannot be decrypted',
  DATA_KEY_INVALID: 'stored data key is invalid',
  DATA_KEY_MISSING: 'data key is missing',
};

export class CredentialVaultError extends Error {
  readonly code: CredentialVaultErrorCode;
  constructor(code: CredentialVaultErrorCode) {
    super(MESSAGES[code]);
    this.name = 'CredentialVaultError';
    this.code = code;
  }
}

/** A row purgeUndecryptable kept although it does not open: for the app to report, never deleted. */
export interface UnopenableRow {
  id: string;
  /** UNKNOWN_FORMAT: not a sealed value of this version. CORRUPT: sealed under the current key but fails to open. */
  reason: 'UNKNOWN_FORMAT' | 'CORRUPT';
}

export interface CredentialVault {
  /**
   * Encrypts and stores a compact credential; returns the new row id. Creates the data key only
   * when none is stored AND the repository holds no rows; otherwise a missing key is DATA_KEY_MISSING.
   */
  save(input: { compact: string; vct: string; issuer: string; keyId: string }): Promise<string>;
  /** Metadata of every row; never decrypts, never reads the data key. */
  list(): Promise<CredentialMetadata[]>;
  /** Metadata of one row, or null; never decrypts, never reads the data key. */
  getMeta(id: string): Promise<CredentialMetadata | null>;
  /** Whether a data key is stored. Reads the secret storage, never writes it. */
  dataKeyState(): Promise<'present' | 'missing'>;
  /** The compact credential. Rejects with NOT_FOUND, DATA_KEY_MISSING, DATA_KEY_INVALID or UNDECRYPTABLE. */
  open(id: string): Promise<string>;
  /** Deletes the row only (idempotent) and leaves its wallet key behind; prefer removeWithKey. */
  remove(id: string): Promise<void>;
  /** Deletes the wallet key, then the row (idempotent; after a failure, calling it again completes it). */
  removeWithKey(id: string, keyStore: WalletKeyStore): Promise<void>;
  /**
   * Deletes exactly the rows sealed under a different data key (their key-check value differs
   * from the current key's) and returns how many, plus the rows that do not open for another
   * reason, which are kept. Rejects with DATA_KEY_MISSING when no data key is stored.
   */
  purgeUndecryptable(): Promise<{ deleted: number; kept: UnopenableRow[] }>;
  /**
   * Deletes every row and the data key. Only for a phone restored from a backup, after the app
   * has decided so with the user (ADR-0009 section 5); the next save creates a fresh data key.
   */
  resetForNewDevice(): Promise<void>;
  setStatus(id: string, status: StoredCredentialStatus, checkedAt: Date): Promise<void>;
}

/** SecretStorage item holding base64url of the 32-byte data key. */
export const DATA_KEY_NAME = 'identra.vault.data-key';
const VERSION = 0x02;
const KCV_BYTES = 8;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + KCV_BYTES;

/** Key-check value: the first 8 bytes of HMAC-SHA256(dataKey, "identra.vault.kcv"). */
function keyCheckValue(dataKey: Uint8Array): Uint8Array {
  const mac = hmac(sha256, dataKey, utf8Encode('identra.vault.kcv'));
  const kcv = mac.slice(0, KCV_BYTES);
  mac.fill(0);
  return kcv;
}

/**
 * Binds a ciphertext to its row and to its header: moving it to another row, editing these
 * columns, or changing the version or key-check value breaks it.
 */
function associatedData(header: Uint8Array, row: Pick<CredentialRow, 'id' | 'vct' | 'issuer' | 'key_id'>): Uint8Array {
  return utf8Encode(JSON.stringify(['identra.credential', base64UrlEncode(header), row.id, row.vct, row.issuer, row.key_id]));
}

function equalConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i]! ^ b[i]!;
  return acc === 0;
}

type Classified = { kind: 'unknown-format' } | { kind: 'other-key' } | { kind: 'ours'; sealed: Uint8Array };

/** Sorts a row by its sealed header only; does not decrypt. */
function classify(row: CredentialRow, kcv: Uint8Array): Classified {
  let sealed: Uint8Array;
  try {
    if (typeof row.ciphertext !== 'string') return { kind: 'unknown-format' };
    sealed = base64UrlDecode(row.ciphertext);
  } catch {
    return { kind: 'unknown-format' };
  }
  if (sealed.length < HEADER_BYTES + NONCE_BYTES + TAG_BYTES || sealed[0] !== VERSION) return { kind: 'unknown-format' };
  return equalConstantTime(sealed.subarray(1, HEADER_BYTES), kcv) ? { kind: 'ours', sealed } : { kind: 'other-key' };
}

/** The plaintext of a row classified as ours, or null when it fails to open. */
function openSealed(row: CredentialRow, sealed: Uint8Array, dataKey: Uint8Array): string | null {
  try {
    const nonce = sealed.subarray(HEADER_BYTES, HEADER_BYTES + NONCE_BYTES);
    const plaintext = gcm(dataKey, nonce, associatedData(sealed.subarray(0, HEADER_BYTES), row)).decrypt(sealed.subarray(HEADER_BYTES + NONCE_BYTES));
    try {
      return utf8Decode(plaintext);
    } finally {
      plaintext.fill(0);
    }
  } catch {
    return null;
  }
}

const metadataOf = (r: CredentialRow): CredentialMetadata => ({
  id: r.id,
  vct: r.vct,
  issuer: r.issuer,
  key_id: r.key_id,
  status_cache: r.status_cache,
  status_checked_at: r.status_checked_at,
  created_at: r.created_at,
});

function requireString(v: unknown, name: string): string {
  if (typeof v !== 'string' || v.length === 0) throw new TypeError(`${name} must be a non-empty string`);
  return v;
}

/**
 * Data-key creation in flight, per SecretStorage object, so that two vaults on one storage cannot
 * each write a different key. Use one vault per storage anyway.
 */
const creating = new WeakMap<SecretStorage, Promise<void>>();

/**
 * The credential vault. The data key is created by the first save into an empty repository and
 * stored under DATA_KEY_NAME; no other path ever writes it. It is read for each operation that
 * needs it and the decoded copy is zeroed after (best-effort: the stored base64url string and the
 * decrypted compact string cannot be erased). Errors carry a code only, never key material or
 * plaintext.
 */
export function createCredentialVault(options: { repository: CredentialRepository; secrets: SecretStorage; random: RandomSource; clock: Clock }): CredentialVault {
  const { repository, secrets, random, clock } = options;

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

  async function requireDataKey(): Promise<Uint8Array> {
    const key = await readDataKey();
    if (!key) throw new CredentialVaultError('DATA_KEY_MISSING');
    return key;
  }

  /** The data key for save(): created only when none is stored and there are no rows. */
  async function dataKeyForSave(): Promise<Uint8Array> {
    const existing = await readDataKey();
    if (existing) return existing;
    let flight = creating.get(secrets);
    if (!flight) {
      flight = (async () => {
        if ((await secrets.get(DATA_KEY_NAME)) !== null) return;
        // Rows without a key mean the key was lost (or a read returned a spurious null):
        // writing a new key here would make every row unreadable.
        if ((await repository.list()).length > 0) throw new CredentialVaultError('DATA_KEY_MISSING');
        const fresh = drawRandom(random, 32);
        try {
          await secrets.set(DATA_KEY_NAME, base64UrlEncode(fresh));
        } finally {
          fresh.fill(0);
        }
      })().finally(() => creating.delete(secrets));
      creating.set(secrets, flight);
    }
    await flight;
    return requireDataKey();
  }

  return {
    async save(input) {
      const compact = requireString(input.compact, 'compact');
      const meta = {
        vct: requireString(input.vct, 'vct'),
        issuer: requireString(input.issuer, 'issuer'),
        key_id: requireString(input.keyId, 'keyId'),
      };
      const key = await dataKeyForSave();
      const plaintext = utf8Encode(compact);
      let row: Pick<CredentialRow, 'id' | 'vct' | 'issuer' | 'key_id' | 'ciphertext'>;
      try {
        const id = base64UrlEncode(drawRandom(random, 16));
        const header = concatBytes(Uint8Array.of(VERSION), keyCheckValue(key));
        const nonce = drawRandom(random, NONCE_BYTES);
        const sealed = gcm(key, nonce, associatedData(header, { id, ...meta })).encrypt(plaintext);
        row = { id, ...meta, ciphertext: base64UrlEncode(concatBytes(header, nonce, sealed)) };
      } finally {
        key.fill(0);
        plaintext.fill(0);
      }
      await repository.insert({ ...row, status_cache: null, status_checked_at: null, created_at: clock.now().toISOString() });
      return row.id;
    },

    async list() {
      return (await repository.list()).map(metadataOf);
    },

    async getMeta(id) {
      const row = await repository.get(id);
      return row ? metadataOf(row) : null;
    },

    async dataKeyState() {
      return (await secrets.get(DATA_KEY_NAME)) === null ? 'missing' : 'present';
    },

    async open(id) {
      const row = await repository.get(id);
      if (!row) throw new CredentialVaultError('NOT_FOUND');
      const key = await requireDataKey();
      try {
        const c = classify(row, keyCheckValue(key));
        const compact = c.kind === 'ours' ? openSealed(row, c.sealed, key) : null;
        if (compact === null) throw new CredentialVaultError('UNDECRYPTABLE');
        return compact;
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
      // Key first: a row without its key is visible (it cannot be presented) and a retry finishes
      // the job; a key without its row would never be found again.
      await keyStore.delete(row.key_id);
      await repository.delete(id);
    },

    async purgeUndecryptable() {
      const key = await requireDataKey();
      const rows = await repository.list();
      let deleted = 0;
      const kept: UnopenableRow[] = [];
      try {
        const kcv = keyCheckValue(key);
        for (const row of rows) {
          const c = classify(row, kcv);
          if (c.kind === 'other-key') {
            await repository.delete(row.id);
            deleted++;
          } else if (c.kind === 'unknown-format') {
            kept.push({ id: row.id, reason: 'UNKNOWN_FORMAT' });
          } else if (openSealed(row, c.sealed, key) === null) {
            kept.push({ id: row.id, reason: 'CORRUPT' });
          }
        }
      } finally {
        key.fill(0);
      }
      return { deleted, kept };
    },

    async resetForNewDevice() {
      for (const row of await repository.list()) await repository.delete(row.id);
      await secrets.delete(DATA_KEY_NAME);
    },

    async setStatus(id, status, checkedAt) {
      if (!['valid', 'revoked', 'suspended', 'unavailable', 'invalid'].includes(status)) throw new TypeError('invalid status');
      if (!(checkedAt instanceof Date) || Number.isNaN(checkedAt.getTime())) throw new TypeError('checkedAt must be a valid Date');
      if (!(await repository.get(id))) throw new CredentialVaultError('NOT_FOUND');
      await repository.update(id, { status_cache: status, status_checked_at: checkedAt.toISOString() });
    },
  };
}
