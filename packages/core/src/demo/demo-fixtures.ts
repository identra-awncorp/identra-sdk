import type { IdentraDidDocument } from '../types/did.js';
import type { IdentraCredentialOffer, IdentraPresentationRequest } from '../types/exchange.js';

export function createDemoDidDocument(did: string): IdentraDidDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'identra-demo-public-key'
        }
      }
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    created: new Date().toISOString()
  };
}

export function createDemoCredentialOffer(input: {
  issuer: string;
  credentialConfigurationId: string;
}): IdentraCredentialOffer {
  return {
    protocol: 'identra-demo-oid4vci',
    credential_issuer: input.issuer,
    credential_configuration_ids: [input.credentialConfigurationId],
    grants: {
      pre_authorized_code: {
        preAuthorizedCode: `preauth-${Date.now().toString(36)}`
      }
    }
  };
}

export function createDemoPresentationRequest(input: {
  verifier: string;
  definitionId: string;
  descriptorId: string;
  schema?: string[];
}): IdentraPresentationRequest {
  return {
    protocol: 'identra-demo-oid4vp',
    client_id: input.verifier,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    nonce: `nonce-${Date.now().toString(36)}`,
    presentation_definition: {
      id: input.definitionId,
      input_descriptors: [
        {
          id: input.descriptorId,
          schema: input.schema
        }
      ]
    }
  };
}
