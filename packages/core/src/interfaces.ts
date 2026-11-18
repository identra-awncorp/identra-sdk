// Interfaces injected into sdk-core (docs/architecture.md section 2). Crypto, HTTP,
// randomness and the clock always come from the caller; sdk-core never reaches for globals.
import type { Check, ErrorCode } from './results.js';
import type { ParsedCertificate } from './x509/parse.js';

export interface EcPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

export interface Signer {
  alg: 'ES256';
  publicJwk: EcPublicJwk;
  /** [leaf, issuing CA], standard base64 DER; wallets have none. */
  x5c?: string[];
  kid?: string;
  /** Returns the 64-byte r||s (JOSE) form, never DER. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface Verifier {
  /**
   * ECDSA P-256 / SHA-256 over `data`. The algorithm is derived from the JWK, never from a JWS header.
   * Must accept both low-S and high-S signatures. Returns false, never throws, on bad input.
   */
  verify(publicJwk: EcPublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface Hasher {
  sha256(data: Uint8Array): Promise<Uint8Array>;
}

export interface RandomSource {
  bytes(n: number): Uint8Array;
}

export interface Clock {
  now(): Date;
}

/**
 * Implementations MUST enforce `timeoutMs` (rejecting when it passes) and a response size limit of
 * their own: sdk-core has no timer and reads `text()` whole (ADR-0019, review F6).
 */
export type HttpFetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export type CertificateProfile = 'vc' | 'status' | 'request' | 'trust-list';

export interface ChainValidationResult {
  ok: boolean;
  code: ErrorCode | null;
  checks: Check[];
  /** Present when ok. */
  leaf?: ParsedCertificate;
  /** base64url (no padding) SHA-256 of the leaf DER, the same value as an OpenID4VP x509_hash. Present when ok. */
  fingerprint?: string;
}

export interface CertificateChainValidator {
  validate(input: {
    x5c: string[];
    profile: CertificateProfile;
    now: Date;
    expectedIssuerUri?: string;
  }): Promise<ChainValidationResult>;
}

export interface StatusChecker {
  /** 'unavailable' = no valid list could be obtained or it failed any check (fail-closed, ADR-0013). */
  check(ref: { uri: string; idx: number }, issuer: { maToChuc: string }): Promise<'valid' | 'revoked' | 'suspended' | 'unavailable'>;
}

export interface TrustEntry {
  maToChuc: string;
  ten: string;
  mucDich: 'vc' | 'status' | 'request';
  vct?: string[];
  congDoan?: string[];
}

export interface TrustRegistry {
  /**
   * Looks up a leaf-certificate fingerprint (base64url SHA-256 of the DER).
   * Returns null when absent or outside validFrom/validUntil at `at`.
   * Rejects with TrustListUnavailableError when no valid trust list is held (ADR-0015 section 6).
   */
  lookup(fingerprint: string, at?: Date): Promise<TrustEntry | null>;
}

export interface DidVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: Record<string, unknown>;
}

export interface DidDocument {
  '@context': string | string[];
  id: string;
  verificationMethod?: DidVerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  keyAgreement?: string[];
}

export interface DidResolutionResult {
  didDocument: DidDocument | null;
  didDocumentMetadata: Record<string, unknown>;
  didResolutionMetadata: { contentType?: string; error?: string; message?: string };
}

/** did:jwk only; kept for tests and a later did:certnet (ADR-0015 section 13). */
export interface DidResolver {
  resolve(did: string, opts?: { versionTime?: string }): Promise<DidResolutionResult>;
}
