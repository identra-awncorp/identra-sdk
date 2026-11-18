// Status lists of the issuers this server operates (ADR-0013 sections 1-5, ADR-0019 section 4):
// random index allocation with rollover to the next list, status changes of allocated indexes only
// (revoked is final), and the signed Status List Token of an existing list, re-signed when the list
// changed or the token is an hour old, with an iat strictly greater than the previous one and never
// more than 5 s ahead of the clock, by a status certificate valid at that moment.
import {
  base64Decode, createStatusList, createStatusListToken, parseCertificate, STATUS_LIST_BYTES, STATUS_LIST_ENTRIES, STATUS_VALUE, statusListEntry,
  statusListFromBytes, type Clock, type RandomSource,
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
  allocate(issuer: string): Promise<{ uri: string; n: number; idx: number }>;
  /**
   * `opts.storage` replaces the service's storage for this call only, e.g. a storage bound to the
   * caller's database transaction, so the status change commits or rolls back with it.
   */
  setStatus(issuer: string, n: number, idx: number, status: StatusListValue, opts?: { storage?: StatusListStorage }): Promise<void>;
  /**
   * The signed Status List Token served at uri(issuer, n); null when list n does not exist (HTTP 404).
   * Throws when there is no token to serve: the signer certificate is not valid now and no held
   * token is inside its exp, or (after a restart) the next iat would be more than 60 s ahead.
   */
  token(issuer: string, n: number): Promise<string | null>;
  uri(issuer: string, n: number): string;
  /** The token held for list n, for monitoring (ADR-0014 section 7): seconds; null when none is held. */
  current(issuer: string, n: number): { iat: number; exp: number; signerNotAfter: number } | null;
}

/** Why a status list was not (re-)signed; the held token, if any, is served meanwhile. */
export type StatusSigningProblem = 'signer_expired' | 'last_iat_in_future';

const RESIGN_AFTER_MS = 3600_000;
const ALLOCATION_ATTEMPTS = 64;
const SAVE_ATTEMPTS = 5;
const MAX_LIST_NUMBER = 999_999_999;
const TOKEN_CACHE_MAX = 1000;
const LIFETIME_SECONDS = 86_400;
/** A re-signed token's iat is at most this far ahead of the clock (a burst of changes waits instead). */
const MAX_IAT_LEAD_SECONDS = 5;
/** Verifiers accept an iat up to 60 s ahead; a stored lastIat beyond that is ignored (and reported). */
const MAX_STORED_LEAD_SECONDS = 60;
const NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export function createStatusListService(options: {
  issuerUri: (name: string) => string;
  keyStore: IssuerKeyStore;
  storage: StatusListStorage;
  random: RandomSource;
  clock: Clock;
  /** Told when a list is not signed as it should be; `issuer` is the organisation name. */
  onError?: (reason: StatusSigningProblem, issuer: string) => void;
}): StatusListService {
  const { issuerUri, keyStore, storage, random, clock, onError } = options;
  const tokens = new Map<string, { token: string; version: number; signedAt: number; iat: number; signerNotAfter: number }>();
  // The last iat this process signed per list: monotonic even when a stored lastIat is ignored.
  const signedIat = new Map<string, number>();
  const reportedFuture = new Set<string>();
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

  /**
   * Signs list n unless that is not allowed now, in which case the held token (if still inside its
   * exp) is served: the signer certificate outside its validity, or an iat that would run more than
   * 5 s ahead of the clock (more than 60 s when nothing is held, i.e. after a restart).
   */
  async function sign(issuer: string, n: number, stored: StoredStatusList): Promise<string> {
    const now = clock.now();
    const nowS = Math.floor(now.getTime() / 1000);
    const key = `${issuer}/${n}`;
    const prior = tokens.get(key);
    const held = prior && (prior.iat + LIFETIME_SECONDS) * 1000 > now.getTime() ? prior : undefined;
    const fallback = (why: string) => {
      if (held) return held.token;
      throw new Error(`status list ${key}: no token can be served (${why})`);
    };
    const signer = await keyStore.signer(issuer, 'status');
    const cert = parseCertificate(base64Decode(signer.x5c![0]!));
    if (now < cert.notBefore || now > cert.notAfter) {
      onError?.('signer_expired', issuer);
      return fallback('signer certificate not valid now');
    }
    let storedIat = stored.lastIat ?? 0;
    if (storedIat > nowS + MAX_STORED_LEAD_SECONDS) {
      if (!reportedFuture.has(key)) onError?.('last_iat_in_future', issuer);
      reportedFuture.add(key);
      storedIat = 0;
    }
    // ADR-0019 section 4: never two tokens with one iat, never an older one (same-second re-sign, clock step back).
    const iat = Math.max(nowS, storedIat + 1, (signedIat.get(key) ?? 0) + 1);
    if (iat > nowS + (held ? MAX_IAT_LEAD_SECONDS : MAX_STORED_LEAD_SECONDS)) return fallback('iat would run ahead of the clock');
    const token = await createStatusListToken({ list: statusListFromBytes(stored.bytes), uri: uri(issuer, n), signer, now: new Date(iat * 1000) });
    signedIat.set(key, iat);
    await storage.recordIat(issuer, n, iat);
    tokens.delete(key);
    tokens.set(key, { token, version: stored.version, signedAt: now.getTime(), iat, signerNotAfter: Math.floor(cert.notAfter.getTime() / 1000) });
    if (tokens.size > TOKEN_CACHE_MAX) tokens.delete(tokens.keys().next().value!);
    return token;
  }

  return {
    uri,
    current(issuer, n) {
      check(issuer, n);
      const held = tokens.get(`${issuer}/${n}`);
      return held ? { iat: held.iat, exp: held.iat + LIFETIME_SECONDS, signerNotAfter: held.signerNotAfter } : null;
    },
    async allocate(issuer) {
      const n = current.get(issuer) ?? 1;
      check(issuer, n);
      for (const list of n < MAX_LIST_NUMBER ? [n, n + 1] : [n]) {
        const idx = await allocateIn(issuer, list);
        if (idx !== null) {
          current.set(issuer, list);
          return { uri: uri(issuer, list), n: list, idx };
        }
      }
      throw new StatusListFullError();
    },
    async setStatus(issuer, n, idx, status, opts) {
      check(issuer, n);
      const storage = opts?.storage ?? options.storage;
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
