// Fetching and caching shared by the status list checker and the trust list registry
// (docs/architecture.md section 5, ADR-0013 section 4, ADR-0015 section 6, ADR-0019):
// - a held copy is used without a refetch while younger than min(ttl, maxFreshSeconds,
//   maxAgeSeconds ?? Infinity); maxFreshSeconds is the hard cap of core (900 s status list,
//   3600 s trust list), a missing ttl means the cap; the age is measured from when this cache
//   fetched it, and a clock that stepped back before that instant makes the copy stale;
// - otherwise refetch; when that fails or yields an invalid token, keep the held copy until its exp;
// - a new copy whose iat is older than the held one never replaces it; one with the SAME iat only
//   when it is the identical token; with `seen`, the last accepted iat survives a restart;
// - concurrent reads of one key share one in-flight load; at most maxEntries keys are held, and an
//   unexpired entry is never evicted to make room (the new token is then used but not cached).
import { utf8Encode } from './encoding.js';
import type { Clock, HttpFetch } from './interfaces.js';
import { CLOCK_SKEW_MS } from './x509/chain.js';

export const FETCH_TIMEOUT_MS = 5000;

/**
 * Optional persistence of what a verifier has already accepted (ADR-0019 section 3), e.g. the
 * wallet's durable storage. Keys: `iat:<url>` (the last accepted iat of the token served at that
 * URL) and `signer-not-before:<trust list url>` (the largest signer_not_before seen). Values are
 * integer seconds. A failing store is treated as empty: the verifier then starts blind, as without one.
 */
export interface SeenStore {
  get(key: string): Promise<number | null>;
  set(key: string, value: number): Promise<void>;
}

export interface CachedToken<T> {
  value: T;
  /** The compact token, to tell an identical re-serve from another token with the same iat. */
  token: string;
  iat: number;
  exp: number;
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

/**
 * GET `url` (https only) with `timeoutMs: 5000` and `maxBytes`; the body when the answer is 200 and
 * fits `maxBytes`, else null. The injected fetch must enforce both.
 */
export async function fetchToken(httpFetch: HttpFetch, url: string, maxBytes: number, accept: string): Promise<string | null> {
  if (typeof url !== 'string' || !url.startsWith('https://')) return null;
  const res = await httpFetch(url, { method: 'GET', headers: { accept }, timeoutMs: FETCH_TIMEOUT_MS, maxBytes });
  if (res.status !== 200) return null;
  const body = await res.text();
  // Bytes, not UTF-16 units: a text of n units can be up to 3n bytes.
  return typeof body === 'string' && body.length <= maxBytes && utf8Encode(body).length <= maxBytes ? body : null;
}

export async function readSeen(seen: SeenStore | undefined, key: string): Promise<number | null> {
  if (!seen) return null;
  try {
    const v = await seen.get(key);
    return Number.isSafeInteger(v) ? v : null;
  } catch {
    return null;
  }
}

export async function writeSeen(seen: SeenStore | undefined, key: string, value: number): Promise<void> {
  try {
    await seen?.set(key, value);
  } catch {
    // Treated like a missing store: the in-memory state still applies.
  }
}

export function createTokenCache<T>(o: {
  /** Fetches and fully verifies a token for `key`; null (or a rejection) when there is no valid one. */
  load: (key: string, now: Date) => Promise<CachedToken<T> | null>;
  clock: Clock;
  maxFreshSeconds: number;
  maxAgeSeconds?: number;
  maxEntries: number;
  seen?: SeenStore;
  /** The URL whose `iat:<url>` record in `seen` belongs to `key`; default the key itself. */
  seenUrl?: (key: string) => string;
}): TokenCache<T> {
  if (o.maxAgeSeconds !== undefined && !(Number.isSafeInteger(o.maxAgeSeconds) && o.maxAgeSeconds >= 0)) {
    throw new TypeError('maxAgeSeconds must be a non-negative integer');
  }
  const held = new Map<string, Held<T>>();
  const inflight = new Map<string, Promise<Held<T> | null>>();
  const nowMs = () => o.clock.now().getTime();
  const usable = (h: Held<T>) => h.exp * 1000 > nowMs() - CLOCK_SKEW_MS;
  const fresh = (h: Held<T>) => {
    const age = nowMs() - h.fetchedAtMs;
    return age >= 0 && age < Math.min(h.ttl ?? o.maxFreshSeconds, o.maxFreshSeconds, o.maxAgeSeconds ?? Infinity) * 1000;
  };

  function accepts(current: Held<T> | undefined, loaded: CachedToken<T>, floor: number | null): boolean {
    if (current) return loaded.iat > current.iat || (loaded.iat === current.iat && loaded.token === current.token);
    // Without a held copy only the persisted iat is known, not the token: an equal iat is accepted.
    return floor === null || loaded.iat >= floor;
  }

  function store(key: string, entry: Held<T>): void {
    if (!held.has(key)) {
      for (const [k, h] of held) {
        if (held.size < o.maxEntries) break;
        if (!usable(h)) held.delete(k);
      }
      if (held.size >= o.maxEntries) return;
    }
    held.delete(key);
    held.set(key, entry);
  }

  async function reload(key: string): Promise<Held<T> | null> {
    const seenKey = `iat:${o.seenUrl ? o.seenUrl(key) : key}`;
    const floor = await readSeen(o.seen, seenKey);
    let loaded: CachedToken<T> | null;
    try {
      loaded = await o.load(key, o.clock.now());
    } catch {
      loaded = null;
    }
    const current = held.get(key);
    if (!loaded || !accepts(current, loaded, floor)) return current ?? null;
    const entry: Held<T> = { ...loaded, fetchedAtMs: nowMs() };
    store(key, entry);
    if (floor === null || loaded.iat > floor) await writeSeen(o.seen, seenKey, loaded.iat);
    return entry;
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
      const r = await pending;
      return r && usable(r) ? r.value : null;
    },
    peek(key) {
      const h = held.get(key);
      if (!h) return undefined;
      const { value, token, iat, exp, ttl } = h;
      return ttl === undefined ? { value, token, iat, exp } : { value, token, iat, exp, ttl };
    },
  };
}
