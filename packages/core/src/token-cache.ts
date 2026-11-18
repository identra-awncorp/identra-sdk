// Fetching and caching shared by the status list checker and the trust list registry
// (docs/architecture.md section 5, ADR-0013 section 4, ADR-0015 section 6):
// - a held copy is used without a refetch while younger than min(ttl, maxAgeSeconds ?? ttl), the age
//   measured from when this cache fetched it (maxAgeSeconds 0: always try to refetch);
// - otherwise refetch; when that fails or yields an invalid token, keep the held copy until its exp;
// - a new copy whose iat is older than the held one never replaces it;
// - concurrent reads of one key share one in-flight load; at most maxEntries keys, oldest evicted.
import type { Clock, HttpFetch } from './interfaces.js';
import { CLOCK_SKEW_MS } from './x509/chain.js';

export const FETCH_TIMEOUT_MS = 5000;

export interface CachedToken<T> {
  value: T;
  iat: number;
  exp: number;
  /** Seconds; a token without ttl is refetched on every read (the held copy still serves as fallback). */
  ttl?: number;
}

interface Held<T> extends CachedToken<T> {
  fetchedAtMs: number;
}

export interface TokenCache<T> {
  /** The usable copy for `key`, reloading per the rules above; null when there is none. Never throws. */
  get(key: string, options?: { force?: boolean }): Promise<T | null>;
  /** The held copy without any reload or expiry check, for monitoring. */
  peek(key: string): CachedToken<T> | undefined;
}

/** GET `url` (https only) with a 5 s timeout; the body when the answer is 200 and the body fits `maxBytes`, else null. */
export async function fetchToken(httpFetch: HttpFetch, url: string, maxBytes: number, accept: string): Promise<string | null> {
  if (typeof url !== 'string' || !url.startsWith('https://')) return null;
  const res = await httpFetch(url, { method: 'GET', headers: { accept }, timeoutMs: FETCH_TIMEOUT_MS });
  if (res.status !== 200) return null;
  const body = await res.text();
  return typeof body === 'string' && body.length <= maxBytes ? body : null;
}

export function createTokenCache<T>(o: {
  /** Fetches and fully verifies a token for `key`; null (or a rejection) when there is no valid one. */
  load: (key: string, now: Date) => Promise<CachedToken<T> | null>;
  clock: Clock;
  maxAgeSeconds?: number;
  maxEntries: number;
}): TokenCache<T> {
  if (o.maxAgeSeconds !== undefined && !(Number.isSafeInteger(o.maxAgeSeconds) && o.maxAgeSeconds >= 0)) {
    throw new TypeError('maxAgeSeconds must be a non-negative integer');
  }
  const held = new Map<string, Held<T>>();
  const inflight = new Map<string, Promise<void>>();
  const nowMs = () => o.clock.now().getTime();
  const usable = (h: Held<T>) => h.exp * 1000 > nowMs() - CLOCK_SKEW_MS;
  const fresh = (h: Held<T>) => nowMs() - h.fetchedAtMs < Math.min(h.ttl ?? 0, o.maxAgeSeconds ?? Infinity) * 1000;

  async function reload(key: string): Promise<void> {
    let loaded: CachedToken<T> | null;
    try {
      loaded = await o.load(key, o.clock.now());
    } catch {
      loaded = null;
    }
    const current = held.get(key);
    if (!loaded || (current && loaded.iat < current.iat)) return;
    held.delete(key);
    held.set(key, { ...loaded, fetchedAtMs: nowMs() });
    while (held.size > o.maxEntries) held.delete(held.keys().next().value!);
  }

  return {
    async get(key, options = {}) {
      const h = held.get(key);
      if (h && !options.force && fresh(h) && usable(h)) return h.value;
      let pending = inflight.get(key);
      if (!pending) {
        pending = reload(key).finally(() => inflight.delete(key));
        inflight.set(key, pending);
      }
      await pending;
      const after = held.get(key);
      return after && usable(after) ? after.value : null;
    },
    peek(key) {
      const h = held.get(key);
      if (!h) return undefined;
      const { value, iat, exp, ttl } = h;
      return ttl === undefined ? { value, iat, exp } : { value, iat, exp, ttl };
    },
  };
}
