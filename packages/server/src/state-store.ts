// Short-lived protocol state (offers, pre-authorized codes, c_nonces, access tokens; later the
// OpenID4VP sessions). The server implements it on Redis; every operation must be atomic on its own.
// Values are strings (JSON); every key carries a TTL and disappears with it.
import type { Clock } from '@identra/sdk-core';

export interface ProtocolStateStore {
  /** Stores or replaces `value` for `ttlSeconds`. Redis: SET key value EX ttl. */
  put(key: string, value: string, ttlSeconds: number): Promise<void>;
  get(key: string): Promise<string | null>;
  /** Get and delete in one atomic step: of two concurrent calls at most one gets the value. Redis: GETDEL. */
  take(key: string): Promise<string | null>;
  /**
   * Adds 1 and returns the new value; a missing key counts from 0 and gets `ttlSeconds` (an existing
   * key keeps its TTL). Redis: INCR, then EXPIRE … NX in the same MULTI.
   */
  increment(key: string, ttlSeconds: number): Promise<number>;
}

const checkTtl = (ttlSeconds: number) => {
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) throw new TypeError('ttlSeconds must be a positive integer');
};

/** In-memory ProtocolStateStore for tests and development; expiry follows the injected clock. */
export function createMemoryStateStore(clock: Clock): ProtocolStateStore {
  const entries = new Map<string, { value: string; expiresAt: number }>();
  const live = (key: string) => {
    const e = entries.get(key);
    if (e && e.expiresAt <= clock.now().getTime()) {
      entries.delete(key);
      return undefined;
    }
    return e;
  };
  return {
    async put(key, value, ttlSeconds) {
      checkTtl(ttlSeconds);
      entries.set(key, { value, expiresAt: clock.now().getTime() + ttlSeconds * 1000 });
    },
    async get(key) {
      return live(key)?.value ?? null;
    },
    async take(key) {
      const e = live(key);
      entries.delete(key);
      return e?.value ?? null;
    },
    async increment(key, ttlSeconds) {
      checkTtl(ttlSeconds);
      const e = live(key);
      const n = (e ? Number(e.value) : 0) + 1;
      entries.set(key, { value: String(n), expiresAt: e?.expiresAt ?? clock.now().getTime() + ttlSeconds * 1000 });
      return n;
    },
  };
}
