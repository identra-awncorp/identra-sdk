// Main entry of @identra/sdk-app: wallet crypto, JWE, keys, credential vault and backup catalogue.
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
