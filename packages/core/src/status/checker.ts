// StatusChecker over HTTP Status List Tokens (ADR-0013 sections 3-4). Fail-closed: any failure is
// 'unavailable', never an exception and never 'valid'.
import type { CertificateChainValidator, Clock, Hasher, HttpFetch, StatusChecker, TrustRegistry, Verifier } from '../interfaces.js';
import { createTokenCache, fetchToken } from '../token-cache.js';
import { STATUS_LIST_ENTRIES, type StatusList } from './list.js';
import { checkStatusListSigner, STATUS_LIST_TOKEN_MAX_BYTES, verifyStatusListToken } from './token.js';

export const STATUS_CACHE_MAX_URIS = 100;
const ANSWERS = ['valid', 'revoked', 'suspended'] as const;

interface HeldList {
  list: StatusList;
  signer: { fingerprint: string; maToChuc: string };
}

export function createStatusListChecker(options: {
  fetch: HttpFetch;
  verifier: Verifier;
  /** Accepted for symmetry with the other factories; hashing happens inside the chain validator. */
  hasher?: Hasher;
  chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry;
  clock: Clock;
  /** Upper bound on the cache age in seconds; 0 = always try to refetch (server-side verifier). */
  maxAgeSeconds?: number;
}): StatusChecker {
  const { fetch, verifier, chainValidator, trustRegistry, clock } = options;
  for (const [fn, name] of [[fetch, 'fetch'], [verifier?.verify, 'verifier'], [chainValidator?.validate, 'chainValidator'], [trustRegistry?.lookup, 'trustRegistry'], [clock?.now, 'clock']] as const) {
    if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  }

  // Keyed by (issuer organisation, uri): a token is verified for the organisation that asked.
  const cache = createTokenCache<HeldList>({
    clock,
    maxEntries: STATUS_CACHE_MAX_URIS,
    ...(options.maxAgeSeconds !== undefined ? { maxAgeSeconds: options.maxAgeSeconds } : {}),
    async load(key, now) {
      const [maToChuc, uri] = JSON.parse(key) as [string, string];
      const token = await fetchToken(fetch, uri, STATUS_LIST_TOKEN_MAX_BYTES, 'application/statuslist+jwt');
      if (token === null) return null;
      const r = await verifyStatusListToken(token, { uri, issuer: { maToChuc }, chainValidator, trustRegistry, verifier, now });
      if (!r.ok) return null;
      return { value: { list: r.list, signer: r.signer }, iat: r.iat, exp: r.exp, ...(r.ttl !== undefined ? { ttl: r.ttl } : {}) };
    },
  });

  return {
    async check(ref, issuer) {
      try {
        if (typeof ref?.uri !== 'string' || !ref.uri.startsWith('https://')) return 'unavailable';
        if (!Number.isSafeInteger(ref.idx) || ref.idx < 0 || ref.idx >= STATUS_LIST_ENTRIES) return 'unavailable';
        if (typeof issuer?.maToChuc !== 'string' || issuer.maToChuc === '') return 'unavailable';
        const held = await cache.get(JSON.stringify([issuer.maToChuc, ref.uri]));
        if (!held) return 'unavailable';
        // A held copy is re-checked on every use: its signer may have left the trust list since.
        if (await checkStatusListSigner(trustRegistry, held.signer, issuer.maToChuc, clock.now())) return 'unavailable';
        return ANSWERS[held.list.getStatus(ref.idx)] ?? 'unavailable';
      } catch {
        return 'unavailable';
      }
    },
  };
}
