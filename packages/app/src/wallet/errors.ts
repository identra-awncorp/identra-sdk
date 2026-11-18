// The closed list of codes a wallet operation fails with (docs/architecture.md section 8). They are
// entries of the SDK catalogue ErrorCodes; ISSUER_MISMATCH is the existing verification code.
import { ErrorCodes, type Check } from '@identra/sdk-core';
import { CredentialVaultError } from '../credential-vault.js';
import { isSecretStorageError, WalletKeyError } from '../key-store.js';

export const WalletErrorCodes = Object.freeze({
  /** The QR code, the offer or the issuer metadata is not one this wallet accepts. */
  OFFER_INVALID: ErrorCodes.OFFER_INVALID,
  /** A non-https URL, or a URL outside the origin of the QR code. */
  URL_NOT_ALLOWED: ErrorCodes.URL_NOT_ALLOWED,
  /** Wrong PIN; the same resolved offer can be accepted again. */
  TX_CODE_WRONG: ErrorCodes.TX_CODE_WRONG,
  /** The offer expired, was used, or was destroyed after five wrong PINs. */
  OFFER_EXPIRED: ErrorCodes.OFFER_EXPIRED,
  /** Unreachable or too slow. */
  NETWORK_ERROR: ErrorCodes.NETWORK_ERROR,
  /** The issuer answered something the protocol does not allow (error, redirect, oversized, malformed, wrong count). */
  ISSUER_ERROR: ErrorCodes.ISSUER_ERROR,
  /** The received credential failed verifyStoredCredential; `checks` says which step. */
  CREDENTIAL_INVALID: ErrorCodes.CREDENTIAL_INVALID,
  /** The credential's `iss` is not the issuer the offer came from. */
  ISSUER_MISMATCH: ErrorCodes.ISSUER_MISMATCH,
  /** The credential is not bound to the key the wallet created for it. */
  CNF_MISMATCH: ErrorCodes.CNF_MISMATCH,
  /** A claim the credential type requires is not among its disclosures. */
  CLAIMS_INCOMPLETE: ErrorCodes.CLAIMS_INCOMPLETE,
  /** The key store or the vault failed. */
  STORAGE_ERROR: ErrorCodes.STORAGE_ERROR,
  CREDENTIAL_NOT_FOUND: ErrorCodes.CREDENTIAL_NOT_FOUND,
  // presentation (architecture section 9)
  /** The request object or the QR code is not one this wallet accepts. */
  REQUEST_INVALID: ErrorCodes.REQUEST_INVALID,
  /** The request expired (on the wallet's clock) before it was answered. */
  REQUEST_EXPIRED: ErrorCodes.REQUEST_EXPIRED,
  /** The request's `client_id` is not the QR's, or not `x509_hash` of its certificate. */
  CLIENT_ID_MISMATCH: ErrorCodes.CLIENT_ID_MISMATCH,
  /** resolve: a warning (the verifier is not in the trust list); submit: refused without allowUntrusted. */
  VERIFIER_NOT_TRUSTED: ErrorCodes.VERIFIER_NOT_TRUSTED,
  TRUST_LIST_UNAVAILABLE: ErrorCodes.TRUST_LIST_UNAVAILABLE,
  ALG_NOT_ALLOWED: ErrorCodes.ALG_NOT_ALLOWED,
  SIGNATURE_INVALID: ErrorCodes.SIGNATURE_INVALID,
  CERT_CHAIN_MALFORMED: ErrorCodes.CERT_CHAIN_MALFORMED,
  CERT_CHAIN_UNTRUSTED: ErrorCodes.CERT_CHAIN_UNTRUSTED,
  CERT_NOT_YET_VALID: ErrorCodes.CERT_NOT_YET_VALID,
  CERT_EXPIRED: ErrorCodes.CERT_EXPIRED,
  CERT_CONSTRAINT_INVALID: ErrorCodes.CERT_CONSTRAINT_INVALID,
  CERT_KEY_NOT_ALLOWED: ErrorCodes.CERT_KEY_NOT_ALLOWED,
  /** The verifier answered the response with something other than 200. */
  VERIFIER_ERROR: ErrorCodes.VERIFIER_ERROR,
  // the credential's wallet key (key store, SecretStorageError)
  KEY_NOT_FOUND: ErrorCodes.KEY_NOT_FOUND,
  /** The platform invalidated the key (Android after a biometric change): the credential must be issued again. */
  KEY_INVALIDATED: ErrorCodes.KEY_INVALIDATED,
  /** The user dismissed the biometric prompt. */
  USER_CANCELLED: ErrorCodes.USER_CANCELLED,
  DEVICE_LOCKED: ErrorCodes.DEVICE_LOCKED,
});

export type WalletErrorCode = (typeof WalletErrorCodes)[keyof typeof WalletErrorCodes];

export interface WalletFailure {
  ok: false;
  code: WalletErrorCode;
  /** With CREDENTIAL_INVALID: every check of the verification. */
  checks?: Check[];
}

/** The wallet code of a key failure: the code of a WalletKeyError or SecretStorageError, else STORAGE_ERROR. */
export function keyFailureCode(e: unknown): WalletErrorCode {
  const code = e instanceof WalletKeyError || isSecretStorageError(e) ? e.code : null;
  if (code === 'KEY_NOT_FOUND' || code === 'KEY_INVALIDATED') return code;
  if (code === 'CANCELLED') return WalletErrorCodes.USER_CANCELLED;
  if (code === 'LOCKED') return WalletErrorCodes.DEVICE_LOCKED;
  return WalletErrorCodes.STORAGE_ERROR;
}

/**
 * The wallet code of a vault failure: CREDENTIAL_NOT_FOUND, the key code of a data-key read the
 * platform refused (SecretStorageError: cancelled, locked, invalidated), else STORAGE_ERROR.
 */
export function vaultFailureCode(e: unknown): WalletErrorCode {
  if (e instanceof CredentialVaultError && e.code === 'NOT_FOUND') return WalletErrorCodes.CREDENTIAL_NOT_FOUND;
  return isSecretStorageError(e) ? keyFailureCode(e) : WalletErrorCodes.STORAGE_ERROR;
}

/** Thrown inside an operation to end it with a code; never leaves the wallet. */
export class Fail extends Error {
  constructor(
    readonly code: WalletErrorCode,
    readonly checks?: Check[],
  ) {
    super(code);
  }
}
