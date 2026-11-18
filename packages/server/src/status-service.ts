// Status lists of the issuers this server operates (ADR-0013 sections 1-5, ADR-0019 section 4):
// random index allocation with rollover to the next list, status changes of allocated indexes only
// (revoked is final), and the signed Status List Token of an existing list, re-signed when the list
// changed or the token is an hour old, with an iat strictly greater than the previous one.
import {
  createStatusList, createStatusListToken, STATUS_LIST_BYTES, STATUS_LIST_ENTRIES, STATUS_VALUE, statusListEntry, statusListFromBytes,
  type Clock, type RandomSource,
} from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

export type StatusListValue = keyof typeof STATUS_VALUE;

export interface StoredStatusList {
  /** The raw 32 768-byte list. */
  bytes: Uint8Array;
  version: number;
  /** iat of the last token signed for this list, seconds; null before the first. */
  lastIat: number | null;
}

/**
 * Persistence of status lists; the server implements it with Postgres. Every method must be
 * atomic on its own; the service never holds a lock across calls.
 */
export interface StatusListStorage {
  /** The list, or null when it does not exist. */
  load(issuer: string, n: number): Promise<StoredStatusList | null>;
  /**
   * Optimistic concurrency: stores `bytes` only when the stored version is `expectedVersion` (null:
   * the list does not exist yet, i.e. create it), then increments the version. False when another
   * writer came first. Postgres: UPDATE … SET bytes = $1, version = version + 1 WHERE … AND
   * version = $2; INSERT … ON CONFLICT DO NOTHING for null.
   */
  save(issuer: string, n: number, bytes: Uint8Array, expectedVersion: number | null): Promise<boolean>;
  /** lastIat = max(lastIat, iat) for an existing list. Postgres: SET last_iat = GREATEST(last_iat, $1). */
  recordIat(issuer: string, n: number, iat: number): Promise<void>;
  /**
   * Marks `idx` of list `n` as used. True only for the one caller that marked it; false when it was
   * already used. This is what keeps two concurrent allocations from returning the same index.
   * Postgres: INSERT INTO status_index (issuer, n, idx) … ON CONFLICT DO NOTHING, true when a row was inserted.
   */
  reserve(issuer: string, n: number, idx: number): Promise<boolean>;
  isReserved(issuer: string, n: number, idx: number): Promise<boolean>;
}

/** A revoked credential stays revoked: any later change is refused. */
export class StatusRevokedError extends Error {
  constructor() {
    super('the credential is revoked; revocation is final');
    this.name = 'StatusRevokedError';
  }
}

/** setStatus on an index that allocate() never returned. */
export class StatusIndexNotAllocatedError extends Error {
  constructor() {
    super('this status list index was never allocated');
    this.name = 'StatusIndexNotAllocatedError';
  }
}

export class StatusListFullError extends Error {
  constructor() {
    super('no unused status list index was found, even in a new list');
    this.name = 'StatusListFullError';
  }
}

export interface StatusListService {
  /** A random unused index, already reserved in storage, of the issuer's current list (or the next one). */
  allocate(issuer: string): Promise<{ uri: string; idx: number }>;
  setStatus(issuer: string, n: number, idx: number, status: StatusListValue): Promise<void>;
  /** The signed Status List Token served at uri(issuer, n); null when list n does not exist (HTTP 404). */
  token(issuer: string, n: number): Promise<string | null>;
  uri(issuer: string, n: number): string;
}

const RESIGN_AFTER_MS = 3600_000;
const ALLOCATION_ATTEMPTS = 64;
const SAVE_ATTEMPTS = 5;
const MAX_LIST_NUMBER = 999_999_999;
const TOKEN_CACHE_MAX = 1000;
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export function createStatusListService(options: {
  issuerUri: (name: string) => string;
  keyStore: IssuerKeyStore;
  storage: StatusListStorage;
  random: RandomSource;
  clock: Clock;
}): StatusListService {
  const { issuerUri, keyStore, storage, random, clock } = options;
  const tokens = new Map<string, { token: string; version: number; signedAt: number }>();
  const signing = new Map<string, Promise<string>>();
  // The list new credentials go to, per issuer; starts at 1 after a restart and moves up as lists fill.
  const current = new Map<string, number>();

  const check = (issuer: string, n: number) => {
    if (typeof issuer !== 'string' || !NAME.test(issuer)) throw new TypeError('issuer must be lower-case words joined by hyphens');
    if (!Number.isSafeInteger(n) || n < 1 || n > MAX_LIST_NUMBER) throw new TypeError('n must be an integer from 1 to 999 999 999');
  };
  const uri = (issuer: string, n: number) => {
    check(issuer, n);
    return `${issuerUri(issuer)}/status/${n}`;
  };

  async function ensureList(issuer: string, n: number): Promise<StoredStatusList> {
    const stored = await storage.load(issuer, n);
    if (stored) return stored;
    await storage.save(issuer, n, new Uint8Array(STATUS_LIST_BYTES), null); // false: created concurrently
    const created = await storage.load(issuer, n);
    if (!created) throw new Error('status list storage did not keep a new list');
    return created;
  }

  async function allocateIn(issuer: string, n: number): Promise<number | null> {
    const stored = await ensureList(issuer, n);
    for (let attempt = 0; attempt < ALLOCATION_ATTEMPTS; attempt++) {
      const b = random.bytes(3);
      // 2^17 entries: the low 17 bits of 3 random bytes are uniform.
      const idx = ((b[0]! << 16) | (b[1]! << 8) | b[2]!) & (STATUS_LIST_ENTRIES - 1);
      if (statusListEntry(stored.bytes, idx) !== 0 || !(await storage.reserve(issuer, n, idx))) continue;
      // Reserved now. An entry that is not 0 was set without an allocation (data from before the
      // isReserved rule): it stays reserved and unused, so no credential is born revoked.
      const after = await storage.load(issuer, n);
      if (after && statusListEntry(after.bytes, idx) === 0) return idx;
    }
    return null;
  }

  async function sign(issuer: string, n: number, stored: StoredStatusList): Promise<string> {
    const now = clock.now();
    // ADR-0019 section 4: never two tokens with one iat, never an older one (same-second re-sign, clock step back).
    const iat = Math.max(Math.floor(now.getTime() / 1000), (stored.lastIat ?? 0) + 1);
    const token = await createStatusListToken({
      list: statusListFromBytes(stored.bytes), uri: uri(issuer, n), signer: await keyStore.signer(issuer, 'status'), now: new Date(iat * 1000),
    });
    await storage.recordIat(issuer, n, iat);
    const key = `${issuer}/${n}`;
    tokens.delete(key);
    tokens.set(key, { token, version: stored.version, signedAt: now.getTime() });
    if (tokens.size > TOKEN_CACHE_MAX) tokens.delete(tokens.keys().next().value!);
    return token;
  }

  return {
    uri,
    async allocate(issuer) {
      const n = current.get(issuer) ?? 1;
      check(issuer, n);
      for (const list of n < MAX_LIST_NUMBER ? [n, n + 1] : [n]) {
        const idx = await allocateIn(issuer, list);
        if (idx !== null) {
          current.set(issuer, list);
          return { uri: uri(issuer, list), idx };
        }
      }
      throw new StatusListFullError();
    },
    async setStatus(issuer, n, idx, status) {
      check(issuer, n);
      if (!Number.isSafeInteger(idx) || idx < 0 || idx >= STATUS_LIST_ENTRIES) throw new RangeError('idx is outside the status list');
      if (!Object.hasOwn(STATUS_VALUE, status)) throw new TypeError('status must be valid, revoked or suspended');
      if (!(await storage.isReserved(issuer, n, idx))) throw new StatusIndexNotAllocatedError();
      const value = STATUS_VALUE[status];
      for (let attempt = 0; attempt < SAVE_ATTEMPTS; attempt++) {
        const stored = await storage.load(issuer, n);
        const list = stored ? statusListFromBytes(stored.bytes) : createStatusList();
        const now = list.getStatus(idx);
        if (now === value) return;
        if (now === STATUS_VALUE.revoked) throw new StatusRevokedError();
        list.setStatus(idx, value);
        if (await storage.save(issuer, n, list.toBytes(), stored?.version ?? null)) return;
      }
      throw new Error('status list: too many concurrent updates, try again');
    },
    async token(issuer, n) {
      check(issuer, n);
      const stored = await storage.load(issuer, n);
      if (!stored) return null;
      const key = `${issuer}/${n}`;
      const held = tokens.get(key);
      const age = clock.now().getTime() - (held?.signedAt ?? 0);
      if (held && held.version === stored.version && age >= 0 && age < RESIGN_AFTER_MS) return held.token;
      let pending = signing.get(key);
      if (!pending) {
        pending = sign(issuer, n, stored).finally(() => signing.delete(key));
        signing.set(key, pending);
      }
      return pending;
    },
  };
}

/** In-memory StatusListStorage for tests and development. */
export function createMemoryStatusListStorage(): StatusListStorage & { reservedCount(issuer: string, n: number): number } {
  const lists = new Map<string, StoredStatusList>();
  const reserved = new Map<string, Set<number>>();
  const tick = () => new Promise<void>((r) => setImmediate(r));
  const set = (key: string) => {
    let s = reserved.get(key);
    if (!s) reserved.set(key, (s = new Set<number>()));
    return s;
  };
  return {
    async load(issuer, n) {
      await tick();
      const s = lists.get(`${issuer}/${n}`);
      return s ? { bytes: s.bytes.slice(), version: s.version, lastIat: s.lastIat } : null;
    },
    async save(issuer, n, bytes, expectedVersion) {
      await tick();
      const key = `${issuer}/${n}`;
      const old = lists.get(key);
      if ((old?.version ?? null) !== expectedVersion) return false;
      lists.set(key, { bytes: bytes.slice(), version: (old?.version ?? 0) + 1, lastIat: old?.lastIat ?? null });
      return true;
    },
    async recordIat(issuer, n, iat) {
      await tick();
      const s = lists.get(`${issuer}/${n}`);
      if (s) s.lastIat = Math.max(s.lastIat ?? 0, iat);
    },
    async reserve(issuer, n, idx) {
      await tick();
      const s = set(`${issuer}/${n}`);
      if (s.has(idx)) return false;
      s.add(idx);
      return true;
    },
    async isReserved(issuer, n, idx) {
      await tick();
      return set(`${issuer}/${n}`).has(idx);
    },
    reservedCount: (issuer, n) => reserved.get(`${issuer}/${n}`)?.size ?? 0,
  };
}
