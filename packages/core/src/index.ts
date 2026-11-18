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
