import {
  createDemoSigner,
  type DidResolver,
  type DidResolutionResult,
  type IdentraCredentialOffer,
  type IdentraPresentationRequest,
  type IdentraVerifiableCredential,
  type IdentraVerifiablePresentation,
  type Signer,
  validateCredential,
  validateCredentialOffer,
  validatePresentationRequest
} from '@identra/sdk-core';

import { InMemoryCredentialStore, type CredentialStore } from './credential-store.js';

export interface IdentraAppSdkConfig {
  resolver: DidResolver;
  signer: Signer;
  credentialStore?: CredentialStore;
}

export interface AcceptCredentialOfferResult {
  accepted: true;
  issuer: string;
  credentialConfigurationIds: string[];
}

export interface CreatePresentationInput {
  request: IdentraPresentationRequest;
  holder: string;
  credentials: IdentraVerifiableCredential[];
}

export interface IdentraAppSdk {
  acceptCredentialOffer(offer: IdentraCredentialOffer): Promise<AcceptCredentialOfferResult>;
  storeCredential(credential: IdentraVerifiableCredential): Promise<void>;
  listCredentials(): Promise<IdentraVerifiableCredential[]>;
  createPresentation(input: CreatePresentationInput): Promise<IdentraVerifiablePresentation>;
  resolveDid(did: string): Promise<DidResolutionResult>;
}

export function createDemoHolderSigner(input: { holderDid: string; verificationMethod?: string }): Signer {
  return createDemoSigner({
    did: input.holderDid,
    verificationMethod: input.verificationMethod
  });
}

export function createIdentraAppSdk(config: IdentraAppSdkConfig): IdentraAppSdk {
  const credentialStore = config.credentialStore ?? new InMemoryCredentialStore();

  return {
    async acceptCredentialOffer(offer) {
      const validation = validateCredentialOffer(offer);
      if (!validation.valid) {
        throw new Error(`Invalid credential offer: ${validation.errors.join('; ')}`);
      }

      return {
        accepted: true,
        issuer: offer.credential_issuer,
        credentialConfigurationIds: offer.credential_configuration_ids
      };
    },

    async storeCredential(credential) {
      const validation = validateCredential(credential);
      if (!validation.valid) {
        throw new Error(`Invalid credential: ${validation.errors.join('; ')}`);
      }

      await credentialStore.saveCredential(credential);
    },

    listCredentials() {
      return credentialStore.listCredentials();
    },

    async createPresentation(input) {
      const requestValidation = validatePresentationRequest(input.request);
      if (!requestValidation.valid) {
        throw new Error(`Invalid presentation request: ${requestValidation.errors.join('; ')}`);
      }

      const presentationWithoutProof: Omit<IdentraVerifiablePresentation, 'proof'> = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: `urn:identra:vp:${Date.now().toString(36)}`,
        type: ['VerifiablePresentation'],
        holder: input.holder,
        verifiableCredential: input.credentials
      };

      const proof = await config.signer.sign(presentationWithoutProof, {
        proofPurpose: 'authentication',
        challenge: input.request.nonce,
        domain: input.request.client_id
      });

      return {
        ...presentationWithoutProof,
        proof
      };
    },

    resolveDid(did) {
      return config.resolver.resolve(did);
    }
  };
}
