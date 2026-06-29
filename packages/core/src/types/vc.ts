import type { IdentraProof } from './proof.js';

export type CredentialSubject = Record<string, unknown> & {
  id?: string;
};

export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose?: string;
  statusListIndex?: string;
  statusListCredential?: string;
}

export interface IdentraCredentialIssuer {
  id: string;
  name?: string;
}

export interface IdentraVerifiableCredential {
  '@context': Array<string | Record<string, unknown>>;
  id: string;
  type: string[];
  issuer: string | IdentraCredentialIssuer;
  validFrom?: string;
  validUntil?: string;
  issuanceDate?: string;
  expirationDate?: string;
  credentialSubject: CredentialSubject | CredentialSubject[];
  credentialStatus?: CredentialStatus;
  proof?: IdentraProof;
}
