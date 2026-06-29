import {
  createDemoCredentialOffer,
  createDemoPresentationRequest,
  createDemoSigner,
  createDemoVerifier,
  stripProof,
  type DidResolver,
  type IdentraCredentialOffer,
  type IdentraDidDocument,
  type IdentraPresentationRequest,
  type IdentraVerifiableCredential,
  type IdentraVerifiablePresentation,
  type Signer,
  type ValidationResult,
  type VerificationSession,
  type Verifier,
  validateCredential,
  validatePresentation
} from '@identra/sdk-core';

import { InMemoryDidRegistry } from './did-registry.js';
import { InMemoryVerificationSessionStore, type VerificationSessionStore } from './session-store.js';

export interface IdentraServerSdkConfig {
  didRegistry?: InMemoryDidRegistry;
  issuerSigner?: Signer;
  verifier?: Verifier;
  sessionStore?: VerificationSessionStore;
}

export interface IssueCredentialInput {
  id?: string;
  issuerDid: string;
  subjectDid: string;
  type: string;
  claims: Record<string, unknown>;
  validFrom?: string;
  validUntil?: string;
}

export interface IdentraServerSdk {
  didResolver: DidResolver;
  registerDidDocument(document: IdentraDidDocument): Promise<void>;
  resolveDid(did: string): ReturnType<DidResolver['resolve']>;
  createCredentialOffer(input: { issuer: string; credentialConfigurationId: string }): IdentraCredentialOffer;
  createPresentationRequest(input: {
    verifier: string;
    definitionId: string;
    descriptorId: string;
    schema?: string[];
  }): IdentraPresentationRequest;
  createVerificationSession(request: IdentraPresentationRequest): Promise<VerificationSession>;
  issueCredential(input: IssueCredentialInput): Promise<IdentraVerifiableCredential>;
  verifyCredential(credential: IdentraVerifiableCredential): Promise<ValidationResult>;
  verifyPresentation(
    presentation: IdentraVerifiablePresentation,
    request?: IdentraPresentationRequest
  ): Promise<ValidationResult>;
}

export function createIdentraServerSdk(config: IdentraServerSdkConfig = {}): IdentraServerSdk {
  const didRegistry = config.didRegistry ?? new InMemoryDidRegistry();
  const issuerSigner = config.issuerSigner ?? createDemoSigner({ did: 'did:identra:demo:issuer' });
  const verifier = config.verifier ?? createDemoVerifier();
  const sessionStore = config.sessionStore ?? new InMemoryVerificationSessionStore();

  return {
    didResolver: didRegistry,

    registerDidDocument(document) {
      return didRegistry.register(document);
    },

    resolveDid(did) {
      return didRegistry.resolve(did);
    },

    createCredentialOffer(input) {
      return createDemoCredentialOffer(input);
    },

    createPresentationRequest(input) {
      return createDemoPresentationRequest(input);
    },

    async createVerificationSession(request) {
      const now = new Date().toISOString();
      const session: VerificationSession = {
        id: `vs-${Date.now().toString(36)}`,
        request,
        status: 'created',
        createdAt: now,
        updatedAt: now
      };

      await sessionStore.save(session);
      return session;
    },

    async issueCredential(input) {
      const credentialWithoutProof: Omit<IdentraVerifiableCredential, 'proof'> = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: input.id ?? `urn:identra:vc:${Date.now().toString(36)}`,
        type: ['VerifiableCredential', input.type],
        issuer: input.issuerDid,
        validFrom: input.validFrom ?? new Date().toISOString(),
        validUntil: input.validUntil,
        credentialSubject: {
          id: input.subjectDid,
          ...input.claims
        }
      };

      const proof = await issuerSigner.sign(credentialWithoutProof, {
        proofPurpose: 'assertionMethod'
      });

      return {
        ...credentialWithoutProof,
        proof
      };
    },

    async verifyCredential(credential) {
      const validation = validateCredential(credential);
      if (!validation.valid) return validation;

      if (!credential.proof) {
        return { valid: false, errors: ['Credential proof is required.'] };
      }

      const proofResult = await verifier.verify(stripProof(credential), credential.proof, {
        proofPurpose: 'assertionMethod'
      });

      return {
        valid: proofResult.verified,
        errors: proofResult.errors
      };
    },

    async verifyPresentation(presentation, request) {
      const validation = validatePresentation(presentation);
      if (!validation.valid) return validation;

      if (!presentation.proof) {
        return { valid: false, errors: ['Presentation proof is required.'] };
      }

      const proofResult = await verifier.verify(stripProof(presentation), presentation.proof, {
        proofPurpose: 'authentication',
        challenge: request?.nonce,
        domain: request?.client_id
      });

      return {
        valid: proofResult.verified,
        errors: proofResult.errors
      };
    }
  };
}
