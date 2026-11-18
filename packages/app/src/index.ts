// Main entry of @identra/sdk-app: wallet crypto, JWE, keys, credential vault, backup catalogue and the wallet object.
// Pure JavaScript on @noble/*; storage, randomness and the clock are injected.
export { nobleVerifier, nobleHasher, createNobleSigner, generateSecretKey, createDerSigningAdapter } from './crypto/noble.js';
export { encryptJwe, decryptJwe, JweError, MAX_JWE_LENGTH, type JweEnc, type JweHeader } from './jwe.js';
export { createSoftwareKeyStore, createInMemorySecretStorage, WalletKeyError, type SecretStorage, type WalletKeyStore } from './key-store.js';
export {
  createCredentialVault,
  createInMemoryCredentialRepository,
  CredentialVaultError,
  CREDENTIALS_TABLE_DDL,
  DATA_KEY_NAME,
  type CredentialMetadata,
  type CredentialRepository,
  type CredentialRow,
  type CredentialStatus,
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
  MAX_CATALOGUE_LENGTH,
  type Catalogue,
  type CatalogueItem,
} from './catalogue.js';
// The wallet object: OpenID4VCI issuance (GĐ5); OpenID4VP presentation comes in GĐ6.
export { createWallet, type Wallet, type WalletConfig } from './wallet/wallet.js';
export { WalletErrorCodes, type WalletErrorCode, type WalletFailure } from './wallet/errors.js';
export { REQUIRED_CLAIMS, type AcceptResult, type DisplayEntry, type ResolvedOffer } from './wallet/issuance.js';
export type { CredentialDetails, CredentialSummary } from './wallet/credentials.js';
export { PROTOCOL_MAX_BYTES, PROTOCOL_TIMEOUT_MS } from './wallet/fetch.js';
