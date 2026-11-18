// Status lists of the issuers this server operates (ADR-0013 sections 1-5): random index
// allocation, status changes (revoked is final) and the signed Status List Token, re-signed when
// the list changed or the cached token is older than one hour.
import {
  createStatusList, createStatusListToken, STATUS_LIST_ENTRIES, STATUS_VALUE, statusListFromBytes,
  type Clock, type RandomSource, type StatusList,
} from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

export type CredentialStatus = keyof typeof STATUS_VALUE;

/**
 * Persistence of status lists; the server implements it with Postgres. Every method must be
 * atomic on its own; the service never holds a lock across calls.
 */
export interface StatusListStorage {
  /** The raw 32 768-byte list and its version, or null when nothing was saved yet. */
  load(issuer: string, n: number): Promise<{ bytes: Uint8Array; version: number } | null>;
  /**
   * Optimistic concurrency: stores `bytes` only when the stored version is `expectedVersion` (null:
   * nothing stored), and then increments the version. False when another writer came first.
   * Postgres: UPDATE ... SET bytes = $1, version = version + 1 WHERE ... AND version = $2 (INSERT for null).
   */
  save(issuer: string, n: number, bytes: Uint8Array, expectedVersion: number | null): Promise<boolean>;
  /**
   * Marks `idx` of list `n` as used. True only for the one caller that marked it; false when it was
   * already used. This is what keeps two concurrent allocations from returning the same index.
   * Postgres: INSERT INTO status_index (issuer, n, idx) ... ON CONFLICT DO NOTHING, true when a row was inserted.
   */
  reserve(issuer: string, n: number, idx: number): Promise<boolean>;
}

/** A revoked credential stays revoked: any later change is refused. */
export class StatusRevokedError extends Error {
  constructor() {
    super('the credential is revoked; revocation is final');
    this.name = 'StatusRevokedError';
  }
}

export class StatusListFullError extends Error {
  constructor() {
    super('no unused status list index was found');
    this.name = 'StatusListFullError';
  }
}

export interface StatusListService {
  /** A random unused index of the issuer's list, already reserved in storage. */
  allocate(issuer: string): Promise<{ uri: string; idx: number }>;
  setStatus(issuer: string, n: number, idx: number, status: CredentialStatus): Promise<void>;
  /** The signed Status List Token served at uri(issuer, n). */
  token(issuer: string, n: number): Promise<string>;
  uri(issuer: string, n: number): string;
}

const RESIGN_AFTER_MS = 3600_000;
const ALLOCATION_ATTEMPTS = 64;
const SAVE_ATTEMPTS = 5;
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export function createStatusListService(options: {
  issuerUri: (name: string) => string;
  keyStore: IssuerKeyStore;
  storage: StatusListStorage;
  random: RandomSource;
  clock: Clock;
}): StatusListService {
  const { issuerUri, keyStore, storage, random, clock } = options;
  const tokens = new Map<string, { token: string; version: number | null; signedAt: number }>();

  const check = (issuer: string, n: number) => {
    if (typeof issuer !== 'string' || !NAME.test(issuer)) throw new TypeError('issuer must be lower-case words joined by hyphens');
    if (!Number.isSafeInteger(n) || n < 1) throw new TypeError('n must be a positive integer');
  };
  const uri = (issuer: string, n: number) => {
    check(issuer, n);
    return `${issuerUri(issuer)}/status/${n}`;
  };
  const listOf = (stored: { bytes: Uint8Array } | null): StatusList => (stored ? statusListFromBytes(stored.bytes) : createStatusList());

  return {
    uri,
    async allocate(issuer) {
      // ponytail: every credential goes to list 1 (131 072 entries per issuer); roll over to list 2 when StatusListFullError appears.
      const n = 1;
      check(issuer, n);
      for (let attempt = 0; attempt < ALLOCATION_ATTEMPTS; attempt++) {
        const b = random.bytes(3);
        // 2^17 entries: the low 17 bits of 3 random bytes are uniform.
        const idx = ((b[0]! << 16) | (b[1]! << 8) | b[2]!) & (STATUS_LIST_ENTRIES - 1);
        if (await storage.reserve(issuer, n, idx)) return { uri: uri(issuer, n), idx };
      }
      throw new StatusListFullError();
    },
    async setStatus(issuer, n, idx, status) {
      check(issuer, n);
      if (!Object.hasOwn(STATUS_VALUE, status)) throw new TypeError('status must be valid, revoked or suspended');
      const value = STATUS_VALUE[status];
      for (let attempt = 0; attempt < SAVE_ATTEMPTS; attempt++) {
        const stored = await storage.load(issuer, n);
        const list = listOf(stored);
        const current = list.getStatus(idx);
        if (current === value) return;
        if (current === STATUS_VALUE.revoked) throw new StatusRevokedError();
        list.setStatus(idx, value);
        if (await storage.save(issuer, n, list.toBytes(), stored?.version ?? null)) return;
      }
      throw new Error('status list: too many concurrent updates, try again');
    },
    async token(issuer, n) {
      const listUri = uri(issuer, n);
      const stored = await storage.load(issuer, n);
      const version = stored?.version ?? null;
      const key = `${issuer}/${n}`;
      const held = tokens.get(key);
      const now = clock.now();
      if (held && held.version === version && now.getTime() - held.signedAt < RESIGN_AFTER_MS) return held.token;
      const token = await createStatusListToken({ list: listOf(stored), uri: listUri, signer: await keyStore.signer(issuer, 'status'), now });
      tokens.set(key, { token, version, signedAt: now.getTime() });
      return token;
    },
  };
}

/** In-memory StatusListStorage for tests and development. */
export function createMemoryStatusListStorage(): StatusListStorage & { reservedCount(issuer: string, n: number): number } {
  const lists = new Map<string, { bytes: Uint8Array; version: number }>();
  const reserved = new Map<string, Set<number>>();
  const tick = () => new Promise<void>((r) => setImmediate(r));
  return {
    async load(issuer, n) {
      await tick();
      const s = lists.get(`${issuer}/${n}`);
      return s ? { bytes: s.bytes.slice(), version: s.version } : null;
    },
    async save(issuer, n, bytes, expectedVersion) {
      await tick();
      const key = `${issuer}/${n}`;
      const current = lists.get(key)?.version ?? null;
      if (current !== expectedVersion) return false;
      lists.set(key, { bytes: bytes.slice(), version: (current ?? 0) + 1 });
      return true;
    },
    async reserve(issuer, n, idx) {
      await tick();
      const key = `${issuer}/${n}`;
      const set = reserved.get(key) ?? new Set<number>();
      reserved.set(key, set);
      if (set.has(idx)) return false;
      set.add(idx);
      return true;
    },
    reservedCount: (issuer, n) => reserved.get(`${issuer}/${n}`)?.size ?? 0,
  };
}
