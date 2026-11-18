// StatusChecker over HTTP Status List Tokens (ADR-0013 sections 3-4, ADR-0019). Fail-closed: any
// failure is 'unavailable', never an exception and never 'valid'.
import type { CertificateChainValidator, Clock, HttpFetch, StatusChecker, TrustRegistry, Verifier } from '../interfaces.js';
import { createTokenCache, fetchToken, type SeenStore } from '../token-cache.js';
import { STATUS_LIST_ENTRIES, type StatusList } from './list.js';
import { checkStatusListSigner, STATUS_LIST_TOKEN_MAX_BYTES, verifyStatusListTokenSigned } from './token.js';

export const STATUS_CACHE_MAX_URIS = 100;
/** ADR-0019 section 1: a held status list is used without a refetch for at most 15 minutes. */
export const STATUS_LIST_MAX_FRESH_SECONDS = 900;
const ANSWERS = ['valid', 'revoked', 'suspended'] as const;

interface HeldList {
  list: StatusList;
  signer: { fingerprint: string; maToChuc: string };
}

export function createStatusListChecker(options: {
  fetch: HttpFetch;
  verifier: Verifier;
  chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry;
  clock: Clock;
  /** Upper bound on the cache age in seconds; 0 = always try to refetch (server-side verifier). */
  maxAgeSeconds?: number;
  /** Keeps the last accepted iat per list URI (key `iat:<uri>`) across restarts. */
  seen?: SeenStore;
}): StatusChecker {
  const { fetch: httpFetch, verifier, chainValidator, trustRegistry, clock, seen } = options;
  for (const [fn, name] of [[httpFetch, 'fetch'], [verifier?.verify, 'verifier'], [chainValidator?.validate, 'chainValidator'], [trustRegistry?.lookup, 'trustRegistry'], [clock?.now, 'clock']] as const) {
    if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  }

  // Keyed by URI: a token is verified once (signer trusted for `status`, organisation matching its
  // trust list entry); each caller then compares the signer's organisation with its own issuer.
  const cache = createTokenCache<HeldList>({
    clock,
    maxFreshSeconds: STATUS_LIST_MAX_FRESH_SECONDS,
    maxEntries: STATUS_CACHE_MAX_URIS,
    ...(options.maxAgeSeconds !== undefined ? { maxAgeSeconds: options.maxAgeSeconds } : {}),
    ...(seen ? { seen } : {}),
    async load(uri, now) {
      const token = await fetchToken(httpFetch, uri, STATUS_LIST_TOKEN_MAX_BYTES, 'application/statuslist+jwt');
      if (token === null) return null;
      const r = await verifyStatusListTokenSigned(token, { uri, issuerMaToChuc: null, chainValidator, trustRegistry, verifier, now });
      if (!r.ok) return null;
      return { value: { list: r.list, signer: r.signer }, token, iat: r.iat, exp: r.exp, ...(r.ttl !== undefined ? { ttl: r.ttl } : {}) };
    },
  });

  return {
    async check(ref, issuer) {
      try {
        if (typeof ref?.uri !== 'string' || !ref.uri.startsWith('https://')) return 'unavailable';
        if (!Number.isSafeInteger(ref.idx) || ref.idx < 0 || ref.idx >= STATUS_LIST_ENTRIES) return 'unavailable';
        if (typeof issuer?.maToChuc !== 'string' || issuer.maToChuc === '') return 'unavailable';
        const held = await cache.get(ref.uri);
        if (!held) return 'unavailable';
        // Re-checked on every use: the signer may have left the trust list since, and the list
        // must be signed by the organisation that issued this credential.
        if (await checkStatusListSigner(trustRegistry, held.signer, issuer.maToChuc, clock.now())) return 'unavailable';
        return ANSWERS[held.list.getStatus(ref.idx)] ?? 'unavailable';
      } catch {
        return 'unavailable';
      }
    },
  };
}
