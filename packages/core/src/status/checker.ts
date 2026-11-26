// StatusChecker over HTTP Status List Tokens (ADR-0013 sections 3-4, ADR-0019). Fail-closed: any
// failure is 'unavailable', never an exception and never 'valid'.
import { isCertNetDid } from '../did-certnet.js';
import { resolveDidVerificationKey } from '../did-jwk.js';
import type { CertificateChainValidator, Clock, DidResolver, EcPublicJwk, HttpFetch, StatusChecker, TrustRegistry, Verifier } from '../interfaces.js';
import { createTokenCache, fetchToken, type SeenStore } from '../token-cache.js';
import { STATUS_LIST_ENTRIES, type StatusList } from './list.js';
import { checkStatusListSigner, STATUS_LIST_TOKEN_MAX_BYTES, verifyDidStatusListToken, verifyStatusListTokenSigned } from './token.js';

export const STATUS_CACHE_MAX_URIS = 100;
/** ADR-0019 section 1: a held status list is used without a refetch for at most 15 minutes. */
export const STATUS_LIST_MAX_FRESH_SECONDS = 900;
const ANSWERS = ['valid', 'revoked', 'suspended'] as const;

interface HeldList {
  list: StatusList;
  /** X.509 issuer: the `status` certificate; DID issuer: the DID key. */
  signer: { fingerprint: string; maToChuc: string } | { kid: string; publicJwk: EcPublicJwk };
}

/**
 * StatusChecker over HTTP. It requests whatever https status-list URI a credential names (the
 * policy has already reduced it to `<iss>/status/<n>`); the injected fetch decides which hosts are
 * reachable at all: the wallet's admits only `/status/<n>` URLs, a server's should answer only its
 * own lists and refuse every other status URL.
 */
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
  /** Resolves DID issuers' keys (ADR-0020 section 6); without it a DID issuer's status is 'unavailable'. */
  didResolver?: DidResolver;
}): StatusChecker {
  const { fetch: httpFetch, verifier, chainValidator, trustRegistry, clock, seen } = options;
  const { didResolver } = options;
  for (const [fn, name] of [[httpFetch, 'fetch'], [verifier?.verify, 'verifier'], [chainValidator?.validate, 'chainValidator'], [trustRegistry?.lookup, 'trustRegistry'], [clock?.now, 'clock']] as const) {
    if (typeof fn !== 'function') throw new TypeError(`${name} is required`);
  }
  if (didResolver !== undefined && typeof didResolver?.resolve !== 'function') throw new TypeError('didResolver must be a DidResolver');

  // Keyed by [kind, issuer organisation or DID, URI]: a token is verified, cached and recorded in
  // `seen` only for the issuer the caller asked about, so a list signed by another trusted
  // organisation or DID at this URI (which could carry a later iat) never displaces or blocks the
  // issuer's own lists, and lists of DID issuers and of X.509 issuers never share an entry.
  type Kind = 'x509' | 'did';
  const keyOf = (kind: Kind, issuer: string, uri: string) => JSON.stringify([kind, issuer, uri]);
  const parseKey = (key: string) => JSON.parse(key) as [Kind, string, string];
  const cache = createTokenCache<HeldList>({
    clock,
    maxFreshSeconds: STATUS_LIST_MAX_FRESH_SECONDS,
    maxEntries: STATUS_CACHE_MAX_URIS,
    ...(options.maxAgeSeconds !== undefined ? { maxAgeSeconds: options.maxAgeSeconds } : {}),
    ...(seen ? { seen } : {}),
    seenUrl: (key) => parseKey(key)[2],
    async load(key, now) {
      const [kind, issuer, uri] = parseKey(key);
      const token = await fetchToken(httpFetch, uri, STATUS_LIST_TOKEN_MAX_BYTES, 'application/statuslist+jwt');
      if (token === null) return null;
      const r = kind === 'did'
        ? await verifyDidStatusListToken(token, { uri, did: issuer, didResolver: didResolver!, verifier, now })
        : await verifyStatusListTokenSigned(token, { uri, issuerMaToChuc: issuer, chainValidator, trustRegistry, verifier, now });
      if (!r.ok) return null;
      return { value: { list: r.list, signer: r.signer }, token, iat: r.iat, exp: r.exp, ...(r.ttl !== undefined ? { ttl: r.ttl } : {}) };
    },
  });

  return {
    async check(ref, issuer) {
      try {
        if (typeof ref?.uri !== 'string' || !ref.uri.startsWith('https://')) return 'unavailable';
        if (!Number.isSafeInteger(ref.idx) || ref.idx < 0 || ref.idx >= STATUS_LIST_ENTRIES) return 'unavailable';
        const { maToChuc, did } = issuer as { maToChuc?: unknown; did?: unknown };
        if (maToChuc !== undefined && did !== undefined) return 'unavailable';
        if (did !== undefined) {
          if (!didResolver || !isCertNetDid(did)) return 'unavailable';
          const held = await cache.get(keyOf('did', did, ref.uri));
          if (!held || !('kid' in held.signer)) return 'unavailable';
          // Re-checked on every use: the key must still be an assertionMethod key of the DID.
          const key = await resolveDidVerificationKey(held.signer.kid, didResolver);
          if (!key.ok || key.publicJwk.x !== held.signer.publicJwk.x || key.publicJwk.y !== held.signer.publicJwk.y) return 'unavailable';
          return ANSWERS[held.list.getStatus(ref.idx)] ?? 'unavailable';
        }
        if (typeof maToChuc !== 'string' || maToChuc === '') return 'unavailable';
        const held = await cache.get(keyOf('x509', maToChuc, ref.uri));
        if (!held || !('fingerprint' in held.signer)) return 'unavailable';
        // Re-checked on every use: the signer may have left the trust list since, and the list
        // must be signed by the organisation that issued this credential.
        if (await checkStatusListSigner(trustRegistry, held.signer, maToChuc, clock.now())) return 'unavailable';
        return ANSWERS[held.list.getStatus(ref.idx)] ?? 'unavailable';
      } catch {
        return 'unavailable';
      }
    },
  };
}
