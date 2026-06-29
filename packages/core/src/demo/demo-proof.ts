import type { IdentraProof, ProofVerificationResult, Signer, SignerOptions, Verifier } from '../types/proof.js';

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(',')}}`;
}

export function stripProof<T extends { proof?: unknown }>(payload: T): Omit<T, 'proof'> {
  const { proof: _proof, ...unsignedPayload } = payload;
  return unsignedPayload;
}

export function createDemoProofValue(payload: Record<string, unknown>): string {
  const input = stableStringify(payload);
  let hash = 0;

  for (let index = 0; index < input.length; index += 1) {
    hash = (hash * 31 + input.charCodeAt(index)) >>> 0;
  }

  return `demo:${hash.toString(36)}:${input.length.toString(36)}`;
}

export function createDemoProof(payload: Record<string, unknown>, options: SignerOptions): IdentraProof {
  const verificationMethod = options.verificationMethod;

  if (!verificationMethod) {
    throw new Error('Demo proof requires a verification method.');
  }

  return {
    type: 'IdentraDemoProof2026',
    created: new Date().toISOString(),
    verificationMethod,
    proofPurpose: options.proofPurpose,
    proofValue: createDemoProofValue(payload),
    domain: options.domain,
    challenge: options.challenge
  };
}

export function createDemoSigner(input: { did: string; verificationMethod?: string }): Signer {
  const verificationMethod = input.verificationMethod ?? `${input.did}#key-1`;

  return {
    did: input.did,
    verificationMethod,
    async sign(payload, options) {
      return createDemoProof(payload, {
        ...options,
        verificationMethod: options.verificationMethod ?? verificationMethod
      });
    }
  };
}

export function createDemoVerifier(): Verifier {
  return {
    async verify(payload, proof, options): Promise<ProofVerificationResult> {
      const errors: string[] = [];

      if (proof.type !== 'IdentraDemoProof2026') errors.push('Unsupported proof type.');
      if (proof.proofValue !== createDemoProofValue(payload)) errors.push('Proof value does not match payload.');
      if (options?.proofPurpose && proof.proofPurpose !== options.proofPurpose) {
        errors.push('Proof purpose does not match.');
      }
      if (options?.domain && proof.domain !== options.domain) errors.push('Proof domain does not match.');
      if (options?.challenge && proof.challenge !== options.challenge) {
        errors.push('Proof challenge does not match.');
      }

      return {
        verified: errors.length === 0,
        checks: ['proof-type', 'proof-value'],
        errors
      };
    }
  };
}
