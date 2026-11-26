// What every part of the wallet object works with; built once by createWallet.
import type { CertificateChainValidator, CertNetNetwork, Clock, Hasher, HttpFetch, RandomSource, StatusChecker, TrustRegistry, Verifier, VerifyCredentialOptions } from '@identra/sdk-core';
import type { CredentialVault } from '../credential-vault.js';
import type { WalletKeyStore } from '../key-store.js';

export interface WalletContext {
  keyStore: WalletKeyStore;
  vault: CredentialVault;
  /** The app's fetch, unguarded: each use wraps it with guardFetch (fetch.ts). */
  fetch: HttpFetch;
  random: RandomSource;
  clock: Clock;
  verifier: Verifier;
  hasher: Hasher;
  chainValidator: CertificateChainValidator;
  trustRegistry: TrustRegistry;
  /** The status checker also checks DID issuers when `dpki` is set. */
  statusChecker: StatusChecker;
  /** The DID trust path (ADR-0020), or null: DID-issued credentials are then refused. */
  dpki: VerifyCredentialOptions['dpki'] | null;
  /** `dpki.network` when the app gave it: a declared DID of another network is refused at resolve. */
  didNetwork: CertNetNetwork | null;
  supportedVcts: readonly string[];
  /** When set, the only origins whose offers and presentation requests the wallet opens. */
  allowedOrigins: readonly string[] | null;
}

/** What verifyStoredCredential needs, from the context; `statusChecker` replaces the context's. */
export function verifyOptionsOf(ctx: WalletContext, statusChecker: StatusChecker = ctx.statusChecker): Omit<VerifyCredentialOptions, 'now'> & { now: Date } {
  return {
    verifier: ctx.verifier, hasher: ctx.hasher, chainValidator: ctx.chainValidator, trustRegistry: ctx.trustRegistry,
    statusChecker, supportedVcts: ctx.supportedVcts, now: ctx.clock.now(), ...(ctx.dpki ? { dpki: ctx.dpki } : {}),
  };
}
