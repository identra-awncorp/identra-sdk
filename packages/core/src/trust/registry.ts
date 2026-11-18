// TrustRegistry over the signed trust list served at `url` (ADR-0015 section 6, ADR-0019), with the
// shared caching rules of docs/architecture.md section 5 (fresh at most 3600 s, held copy until exp,
// no older iat) and the signer_not_before rule.
import type { CertificateChainValidator, Clock, HttpFetch, TrustEntry, TrustRegistry, Verifier } from '../interfaces.js';
import { TrustListUnavailableError } from '../results.js';
import { createTokenCache, fetchToken, readSeen, writeSeen, type SeenStore } from '../token-cache.js';
import { CLOCK_SKEW_MS } from '../x509/chain.js';
import type { TrustListPayload } from './payload.js';
import { TRUST_LIST_TOKEN_MAX_BYTES, verifyTrustListToken } from './token.js';

/** ADR-0019 section 1: a held trust list is used without a refetch for at most one hour. */
export const TRUST_LIST_MAX_FRESH_SECONDS = 3600;

interface Indexed {
  entry: TrustEntry;
  /** Milliseconds; absent for a verifier without validFrom / validUntil. */
  from?: number;
  until?: number;
}

interface HeldTrustList {
  index: Map<string, Indexed>;
  issuers: number;
  verifiers: number;
}

export interface SignedTrustListRegistry extends TrustRegistry {
  /** Refetches now regardless of the cache age; true when a usable trust list is held afterwards. */
  refresh(): Promise<boolean>;
  /** The held copy for monitoring (ADR-0014 section 7), or null; never triggers a fetch. */
  current(): { iat: number; exp: number; ttl: number; issuers: number; verifiers: number } | null;
}

function index(p: TrustListPayload): HeldTrustList {
  const map = new Map<string, Indexed>();
  for (const e of p.issuers) {
    const from = new Date(e.validFrom).getTime();
    const until = new Date(e.validUntil).getTime();
    for (const c of e.chung_thu) {
      const entry: TrustEntry = { maToChuc: e.ma_to_chuc, ten: e.ten, mucDich: c.muc_dich, vct: [...e.vct] };
      if (e.cong_doan) entry.congDoan = [...e.cong_doan];
      map.set(c.sha256, { entry, from, until });
    }
  }
  for (const e of p.verifiers) {
    for (const c of e.chung_thu) {
      const indexed: Indexed = { entry: { maToChuc: e.ma_to_chuc, ten: e.ten, mucDich: c.muc_dich } };
      if (e.validFrom !== undefined && e.validUntil !== undefined) {
        indexed.from = new Date(e.validFrom).getTime();
        indexed.until = new Date(e.validUntil).getTime();
      }
      map.set(c.sha256, indexed);
    }
  }
  return { index: map, issuers: p.issuers.length, verifiers: p.verifiers.length };
}

/** A copy, so that no caller can change what the registry holds. */
function copy(e: TrustEntry): TrustEntry {
  const out: TrustEntry = { maToChuc: e.maToChuc, ten: e.ten, mucDich: e.mucDich };
  if (e.vct) out.vct = [...e.vct];
  if (e.congDoan) out.congDoan = [...e.congDoan];
  return out;
}

export function createSignedTrustListRegistry(options: {
  url: string;
  fetch: HttpFetch;
  verifier: Verifier;
  chainValidator: CertificateChainValidator;
  clock: Clock;
  maxAgeSeconds?: number;
  /** Keeps `iat:<url>` and `signer-not-before:<url>` across restarts (ADR-0019 section 3). */
  seen?: SeenStore;
}): SignedTrustListRegistry {
  const { url, fetch: httpFetch, verifier, chainValidator, clock, seen } = options;
  if (typeof url !== 'string' || !url.startsWith('https://')) throw new TypeError('url must be an https URL');
  for (const [fn, name] of [[httpFetch, 'fetch'], [verifier?.verify, 'verifier'], [chainValidator?.validate, 'chainValidator'], [clock?.now, 'clock']] as const) {
    if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  }
  // The largest signer_not_before of a verified list: in memory, and in `seen` when given.
  const notBeforeKey = `signer-not-before:${url}`;
  let minSignerNotBefore = 0;
  const cache = createTokenCache<HeldTrustList>({
    clock,
    maxFreshSeconds: TRUST_LIST_MAX_FRESH_SECONDS,
    maxEntries: 1,
    ...(options.maxAgeSeconds !== undefined ? { maxAgeSeconds: options.maxAgeSeconds } : {}),
    ...(seen ? { seen } : {}),
    async load(key, now) {
      const token = await fetchToken(httpFetch, key, TRUST_LIST_TOKEN_MAX_BYTES, 'application/jwt');
      if (token === null) return null;
      minSignerNotBefore = Math.max(minSignerNotBefore, (await readSeen(seen, notBeforeKey)) ?? 0);
      const r = await verifyTrustListToken(token, { chainValidator, verifier, now, ...(minSignerNotBefore > 0 ? { minSignerNotBefore } : {}) });
      if (!r.ok) return null;
      const raised = r.payload.signer_not_before;
      if (raised !== undefined && raised > minSignerNotBefore) {
        minSignerNotBefore = raised;
        await writeSeen(seen, notBeforeKey, raised);
      }
      return { value: index(r.payload), token, iat: r.payload.iat, exp: r.payload.exp, ttl: r.payload.ttl };
    },
  });

  return {
    async lookup(fingerprint, at) {
      const t = (at ?? clock.now()).getTime();
      if (Number.isNaN(t)) throw new TypeError('at must be a valid Date');
      const held = await cache.get(url);
      if (!held) throw new TrustListUnavailableError();
      const found = typeof fingerprint === 'string' ? held.index.get(fingerprint) : undefined;
      if (!found) return null;
      // The usual 60 s clock skew applies to the validity window.
      if (found.from !== undefined && (t < found.from - CLOCK_SKEW_MS || t > found.until! + CLOCK_SKEW_MS)) return null;
      return copy(found.entry);
    },
    async refresh() {
      return (await cache.get(url, { force: true })) !== null;
    },
    current() {
      const h = cache.peek(url);
      if (!h) return null;
      return { iat: h.iat, exp: h.exp, ttl: h.ttl!, issuers: h.value.issuers, verifiers: h.value.verifiers };
    },
  };
}
