export type ProofPurpose = 'assertionMethod' | 'authentication';

export type IdentraProofType = 'IdentraDemoProof2026';

export interface IdentraProof {
  type: IdentraProofType | string;
  created: string;
  verificationMethod: string;
  proofPurpose: ProofPurpose;
  proofValue: string;
  domain?: string;
  challenge?: string;
}

export interface SignerOptions {
  proofPurpose: ProofPurpose;
  verificationMethod?: string;
  domain?: string;
  challenge?: string;
}

export interface Signer {
  did: string;
  verificationMethod: string;
  sign(payload: Record<string, unknown>, options: SignerOptions): Promise<IdentraProof>;
}

export interface ProofVerificationResult {
  verified: boolean;
  checks: string[];
  errors: string[];
}

export interface Verifier {
  verify(
    payload: Record<string, unknown>,
    proof: IdentraProof,
    options?: Partial<SignerOptions>
  ): Promise<ProofVerificationResult>;
}
