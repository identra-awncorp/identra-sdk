// The closed list of codes a wallet operation fails with (docs/architecture.md section 8). They are
// entries of the SDK catalogue ErrorCodes; ISSUER_MISMATCH is the existing verification code.
import { ErrorCodes, type Check } from '@identra/sdk-core';

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
});

export type WalletErrorCode = (typeof WalletErrorCodes)[keyof typeof WalletErrorCodes];

export interface WalletFailure {
  ok: false;
  code: WalletErrorCode;
  /** With CREDENTIAL_INVALID: every check of the verification. */
  checks?: Check[];
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
