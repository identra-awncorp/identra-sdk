// Main entry of @identra/sdk-app: wallet crypto, JWE, keys, credential vault, backup catalogue and the wallet object.
// Pure JavaScript on @noble/*; storage, randomness and the clock are injected.
export { nobleVerifier, nobleHasher, createNobleSigner, generateSecretKey, createDerSigningAdapter } from './crypto/noble.js';
export { encryptJwe, decryptJwe, JweError, MAX_JWE_LENGTH, type JweEnc, type JweHeader } from './jwe.js';
export {
  createSoftwareKeyStore,
  createInMemorySecretStorage,
  isSecretStorageError,
  SecretStorageError,
  WalletKeyError,
  type SecretStorage,
  type SecretStorageErrorCode,
  type WalletKeyErrorCode,
  type WalletKeyStore,
} from './key-store.js';
export {
  createCredentialVault,
  createInMemoryCredentialRepository,
  CredentialVaultError,
  CREDENTIALS_TABLE_DDL,
  DATA_KEY_NAME,
  type CredentialMetadata,
  type CredentialRepository,
  type CredentialRow,
  type StoredCredentialStatus,
  type CredentialVault,
  type CredentialVaultErrorCode,
  type UnopenableRow,
} from './credential-vault.js';
export { RandomSourceError } from './random.js';
export {
  buildCatalogue,
  serializeCatalogue,
  parseCatalogue,
  diffCatalogue,
  mergeCatalogue,
  MAX_CATALOGUE_LENGTH,
  type Catalogue,
  type CatalogueItem,
} from './catalogue.js';
// The wallet object: OpenID4VCI issuance (GĐ5) and OpenID4VP presentation (GĐ6).
export { createWallet, type Wallet, type WalletConfig } from './wallet/wallet.js';
export { WalletErrorCodes, type WalletErrorCode, type WalletFailure } from './wallet/errors.js';
export { MAX_DID_LENGTH, REQUIRED_CLAIMS, type AcceptFailure, type AcceptResult, type DisplayEntry, type ResolvedOffer } from './wallet/issuance.js';
export type { CredentialDetails, CredentialSummary, WalletCredentialStatus } from './wallet/credentials.js';
export { MAX_PRESENTATION_SENDS, type PresentationMatch, type ResolvedPresentation, type VerifierIdentity } from './wallet/presentation.js';
export { DEFAULT_MAX_BYTES, PROTOCOL_MAX_BYTES, PROTOCOL_TIMEOUT_MS } from './wallet/fetch.js';
