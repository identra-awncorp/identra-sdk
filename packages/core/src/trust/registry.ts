// TrustRegistry over the signed trust list served at `url` (ADR-0015 section 6), with the shared
// caching rules of docs/architecture.md section 5 (ttl 3600 s, held copy until exp, no older iat).
import type { CertificateChainValidator, Clock, HttpFetch, TrustEntry, TrustRegistry, Verifier } from '../interfaces.js';
import { TrustListUnavailableError } from '../results.js';
import { createTokenCache, fetchToken } from '../token-cache.js';
import type { TrustListPayload } from './payload.js';
import { TRUST_LIST_TOKEN_MAX_BYTES, verifyTrustListToken } from './token.js';

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
}): SignedTrustListRegistry {
  const { url, fetch, verifier, chainValidator, clock } = options;
  if (typeof url !== 'string' || !url.startsWith('https://')) throw new TypeError('url must be an https URL');
  for (const [fn, name] of [[fetch, 'fetch'], [verifier?.verify, 'verifier'], [chainValidator?.validate, 'chainValidator'], [clock?.now, 'clock']] as const) {
    if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  }
  const cache = createTokenCache<HeldTrustList>({
    clock,
    maxEntries: 1,
    ...(options.maxAgeSeconds !== undefined ? { maxAgeSeconds: options.maxAgeSeconds } : {}),
    async load(key, now) {
      const token = await fetchToken(fetch, key, TRUST_LIST_TOKEN_MAX_BYTES, 'application/jwt');
      if (token === null) return null;
      const r = await verifyTrustListToken(token, { chainValidator, verifier, now });
      if (!r.ok) return null;
      return { value: index(r.payload), iat: r.payload.iat, exp: r.payload.exp, ttl: r.payload.ttl };
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
      if (found.from !== undefined && (t < found.from || t > found.until!)) return null;
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
