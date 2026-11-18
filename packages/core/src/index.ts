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
  verifyCredential,
  type CredentialVerificationResult,
  type VerifiedCredential,
  type VerifyCredentialOptions,
} from './sd-jwt/verify.js';
