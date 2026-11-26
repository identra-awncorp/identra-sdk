// Result model and error codes (docs/architecture.md section 3, ADR-0006 section 5).
// UI and logs branch on these codes, never on messages.

export const ErrorCodes = Object.freeze({
  // 1 structure
  MALFORMED: 'MALFORMED',
  TYP_INVALID: 'TYP_INVALID',
  TOO_LARGE: 'TOO_LARGE',
  // 2 algorithm
  ALG_NOT_ALLOWED: 'ALG_NOT_ALLOWED',
  // 3 certificate_chain
  CERT_CHAIN_MALFORMED: 'CERT_CHAIN_MALFORMED',
  CERT_CHAIN_UNTRUSTED: 'CERT_CHAIN_UNTRUSTED',
  CERT_NOT_YET_VALID: 'CERT_NOT_YET_VALID',
  CERT_EXPIRED: 'CERT_EXPIRED',
  CERT_CONSTRAINT_INVALID: 'CERT_CONSTRAINT_INVALID',
  CERT_KEY_NOT_ALLOWED: 'CERT_KEY_NOT_ALLOWED',
  ISSUER_MISMATCH: 'ISSUER_MISMATCH',
  // 3 did_resolution (ADR-0020 section 4); ISSUER_MISMATCH, KEY_NOT_FOUND, DID_RESOLUTION_FAILED and ALG_NOT_ALLOWED are reused
  /** The CertNet gateway gave no usable answer: "not checked yet", never "forged". */
  DID_RESOLUTION_UNAVAILABLE: 'DID_RESOLUTION_UNAVAILABLE',
  // 4 signature
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  // 5 validity_time
  NOT_YET_VALID: 'NOT_YET_VALID',
  EXPIRED: 'EXPIRED',
  // 6 credential_type
  VCT_UNSUPPORTED: 'VCT_UNSUPPORTED',
  // 7 issuer_trust
  ISSUER_NOT_TRUSTED: 'ISSUER_NOT_TRUSTED',
  TRUST_LIST_UNAVAILABLE: 'TRUST_LIST_UNAVAILABLE',
  // 8 status
  REVOKED: 'REVOKED',
  SUSPENDED: 'SUSPENDED',
  STATUS_UNAVAILABLE: 'STATUS_UNAVAILABLE',
  // 9 holder_binding
  DISCLOSURE_INVALID: 'DISCLOSURE_INVALID',
  KB_INVALID: 'KB_INVALID',
  NONCE_MISMATCH: 'NONCE_MISMATCH',
  AUD_MISMATCH: 'AUD_MISMATCH',
  // 10 product_chain
  CHAIN_BROKEN: 'CHAIN_BROKEN',
  // other
  CLIENT_ID_MISMATCH: 'CLIENT_ID_MISMATCH',
  VERIFIER_NOT_TRUSTED: 'VERIFIER_NOT_TRUSTED',
  DID_RESOLUTION_FAILED: 'DID_RESOLUTION_FAILED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  SKIPPED: 'SKIPPED',
  // wallet operations (sdk-app, docs/architecture.md section 8); ISSUER_MISMATCH above is reused
  OFFER_INVALID: 'OFFER_INVALID',
  URL_NOT_ALLOWED: 'URL_NOT_ALLOWED',
  TX_CODE_WRONG: 'TX_CODE_WRONG',
  TX_CODE_REQUIRED: 'TX_CODE_REQUIRED',
  OFFER_EXPIRED: 'OFFER_EXPIRED',
  NETWORK_ERROR: 'NETWORK_ERROR',
  ISSUER_ERROR: 'ISSUER_ERROR',
  CREDENTIAL_INVALID: 'CREDENTIAL_INVALID',
  CNF_MISMATCH: 'CNF_MISMATCH',
  CLAIMS_INCOMPLETE: 'CLAIMS_INCOMPLETE',
  STORAGE_ERROR: 'STORAGE_ERROR',
  CREDENTIAL_NOT_FOUND: 'CREDENTIAL_NOT_FOUND',
  // presentation (docs/architecture.md section 9); CLIENT_ID_MISMATCH, VERIFIER_NOT_TRUSTED, CERT_*,
  // SIGNATURE_INVALID, ALG_NOT_ALLOWED and TRUST_LIST_UNAVAILABLE above are reused
  QUERY_NOT_SATISFIED: 'QUERY_NOT_SATISFIED',
  TOO_MANY_ATTEMPTS: 'TOO_MANY_ATTEMPTS',
  REQUEST_INVALID: 'REQUEST_INVALID',
  REQUEST_EXPIRED: 'REQUEST_EXPIRED',
  VERIFIER_ERROR: 'VERIFIER_ERROR',
  KEY_INVALIDATED: 'KEY_INVALIDATED',
  USER_CANCELLED: 'USER_CANCELLED',
  DEVICE_LOCKED: 'DEVICE_LOCKED',
} as const);

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

/** Credential checks (architecture section 3) and the steps of certificate chain validation (section 4). */
export type CheckId =
  | 'structure'
  | 'algorithm'
  | 'certificate_chain'
  /** Step 3 on the DID trust path (ADR-0020 section 4), in place of certificate_chain. */
  | 'did_resolution'
  | 'signature'
  | 'validity_time'
  | 'credential_type'
  | 'issuer_trust'
  | 'status'
  | 'holder_binding'
  | 'product_chain'
  | 'query'
  | 'chain_format'
  | 'chain_signatures'
  | 'chain_validity'
  | 'chain_constraints'
  | 'leaf_key'
  | 'issuer_uri';

export interface Check {
  id: CheckId;
  ok: boolean;
  code: ErrorCode | null;
  skipped?: true;
  /** For logs only; never contains claim values, credentials, disclosures or KB-JWTs (ADR-0014 section 4). */
  detail?: string;
}

/** ok = every listed check is ok. */
export interface VerificationResult {
  ok: boolean;
  checks: Check[];
}

/**
 * Thrown by a TrustRegistry when it holds no valid trust list (ADR-0015 section 6), and by a
 * DidTrustRegistry when it got no usable answer (ADR-0020 section 5).
 */
export class TrustListUnavailableError extends Error {
  constructor(message = 'no valid trust list is held') {
    super(message);
    this.name = 'TrustListUnavailableError';
  }
}
