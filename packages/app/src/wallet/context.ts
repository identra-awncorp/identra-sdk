// What every part of the wallet object works with; built once by createWallet.
import type { CertificateChainValidator, Clock, Hasher, HttpFetch, RandomSource, StatusChecker, TrustRegistry, Verifier } from '@identra/sdk-core';
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
  statusChecker: StatusChecker;
  supportedVcts: readonly string[];
}
