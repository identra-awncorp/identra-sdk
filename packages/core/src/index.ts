// Main entry of @identra/sdk-core. Imports no platform library and touches no platform global.
export * from './encoding.js';
export * from './interfaces.js';
export * from './results.js';
export * from './ecdsa-der.js';
export * from './jwk.js';
export * from './jws.js';
export * from './did-jwk.js';
export { parseCertificate, type ParsedCertificate } from './x509/parse.js';
export { createCertificateChainValidator, MAX_CERTIFICATE_BYTES, CLOCK_SKEW_MS } from './x509/chain.js';
export * from './sd-jwt/credential-types.js';
export { issueCredential, issueDiploma, issueProductEvent, type IssuerContext, type IssueCredentialInput } from './sd-jwt/issue.js';
export { createPresentation } from './sd-jwt/present.js';
export { decodeCredentialUnverified, type UnverifiedCredential } from './sd-jwt/compact.js';
export {
  verifyPresentation,
  verifyStoredCredential,
  type CredentialVerificationResult,
  type VerifiedCredential,
  type VerifyCredentialOptions,
  type VerifyPresentationOptions,
} from './sd-jwt/verify.js';
// Status list and trust list (GĐ7a, docs/architecture.md section 7).
export {
  createStatusList,
  decodeStatusList,
  statusListEntry,
  statusListFromBytes,
  STATUS_LIST_BYTES,
  STATUS_LIST_ENTRIES,
  STATUS_VALUE,
  type StatusList,
  type StatusValue,
} from './status/list.js';
export {
  createStatusListToken,
  STATUS_LIST_TOKEN_MAX_BYTES,
  STATUS_LIST_TOKEN_TYP,
  verifyStatusListToken,
  type VerifiedStatusListToken,
} from './status/token.js';
export { createStatusListChecker, STATUS_CACHE_MAX_URIS, STATUS_LIST_MAX_FRESH_SECONDS } from './status/checker.js';
export { MAX_TOKEN_LIFETIME_SECONDS, type TokenFailure, type TokenFailureReason } from './signed-token.js';
export type { SeenStore } from './token-cache.js';
export {
  isFingerprint,
  TRUST_LIST_MAX_ENTRIES,
  validateTrustListContent,
  validateTrustListPayload,
  type TrustListCertificate,
  type TrustListContent,
  type TrustListIssuer,
  type TrustListPayload,
  type TrustListVerifier,
} from './trust/payload.js';
export { createTrustListToken, TRUST_LIST_TOKEN_MAX_BYTES, TRUST_LIST_TOKEN_TYP, verifyTrustListToken, type VerifiedTrustListToken } from './trust/token.js';
export { createSignedTrustListRegistry, TRUST_LIST_MAX_FRESH_SECONDS, type SignedTrustListRegistry } from './trust/registry.js';
export { createMappedFetch } from './mapped-fetch.js';
