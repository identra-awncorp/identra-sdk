// createWallet: the object the app and the simulated wallet use (docs/architecture.md section 8).
// It builds the chain validator, the trust registry and the status checker once.
import {
  createCertificateChainValidator, createSignedTrustListRegistry, createStatusListChecker, TRUST_LIST_TOKEN_MAX_BYTES, VCT,
  type Clock, type Hasher, type HttpFetch, type RandomSource, type SeenStore, type Verifier,
} from '@identra/sdk-core';
import type { CredentialVault } from '../credential-vault.js';
import { nobleHasher, nobleVerifier } from '../crypto/noble.js';
import type { WalletKeyStore } from '../key-store.js';
import type { WalletContext } from './context.js';
import { createCredentials } from './credentials.js';
import { guardFetch, httpsOrigin, PROTOCOL_TIMEOUT_MS } from './fetch.js';
import { createIssuance, REQUIRED_CLAIMS } from './issuance.js';
import { createPresentations } from './presentation.js';

export interface WalletConfig {
  keyStore: WalletKeyStore;
  vault: CredentialVault;
  /** Must not follow redirects and should cap response sizes itself (see guardFetch). */
  fetch: HttpFetch;
  random: RandomSource;
  clock: Clock;
  /** Pinned Identra root certificate(s), DER. */
  trustedRoots: Uint8Array[];
  /** `https://api-identra.awncorp.vn/trust-list`. */
  trustListUrl: string;
  /** Credential types the wallet accepts; holder-bound types only. Default: the diploma. */
  supportedVcts?: string[];
  /** Persistence of the last accepted list `iat`s (architecture section 5). */
  seen?: SeenStore;
  verifier?: Verifier;
  hasher?: Hasher;
  /**
   * Exact origins (`https://host[:port]`) whose offers and presentation requests the wallet opens;
   * a QR code naming any other origin is URL_NOT_ALLOWED before any request. The Identra app sets
   * the API origin (ADR-0010 point 6). Unset: any acceptable https host.
   */
  allowedOrigins?: string[];
}

/** A status list URL as the credential policy admits it: `<iss>/status/<n>` (checked again by the policy). */
const STATUS_LIST_URL = /\/status\/[1-9][0-9]{0,8}$/;

export function createWallet(config: WalletConfig) {
  const { keyStore, vault, fetch, random, clock, trustedRoots, trustListUrl, seen } = config;
  const verifier = config.verifier ?? nobleVerifier;
  const hasher = config.hasher ?? nobleHasher;
  const supportedVcts = config.supportedVcts ?? [VCT.diploma];
  if (typeof fetch !== 'function') throw new TypeError('fetch is required');
  if (httpsOrigin(trustListUrl) === null) throw new TypeError('trustListUrl must be an https URL');
  for (const vct of supportedVcts) if (!Object.hasOwn(REQUIRED_CLAIMS, vct)) throw new TypeError(`${vct} is not a credential type the wallet can receive`);
  const allowedOrigins = config.allowedOrigins === undefined ? null : [...config.allowedOrigins];
  if (allowedOrigins && !allowedOrigins.every((o) => httpsOrigin(o) === o)) throw new TypeError('allowedOrigins must be exact https origins of acceptable hosts');

  // The trust list and the status lists the credential policy names; nothing else.
  const listsFetch = guardFetch(fetch, {
    allow: (url) => url === trustListUrl || STATUS_LIST_URL.test(url),
    maxBytes: TRUST_LIST_TOKEN_MAX_BYTES, // the larger of the two lists; each call asks for its own cap
    timeoutMs: PROTOCOL_TIMEOUT_MS,
  });
  const chainValidator = createCertificateChainValidator({ trustedRoots, verifier, hasher });
  const trustRegistry = createSignedTrustListRegistry({ url: trustListUrl, fetch: listsFetch, verifier, chainValidator, clock, ...(seen ? { seen } : {}) });
  const statusChecker = createStatusListChecker({ fetch: listsFetch, verifier, chainValidator, trustRegistry, clock, ...(seen ? { seen } : {}) });
  const ctx: WalletContext = { keyStore, vault, fetch, random, clock, verifier, hasher, chainValidator, trustRegistry, statusChecker, supportedVcts, allowedOrigins };

  return {
    offers: createIssuance(ctx),
    credentials: createCredentials(ctx),
    presentations: createPresentations(ctx),
  };
}

export type Wallet = ReturnType<typeof createWallet>;
