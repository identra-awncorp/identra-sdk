export interface CredentialOfferGrant {
  preAuthorizedCode?: string;
  txCodeRequired?: boolean;
}

export interface IdentraCredentialOffer {
  protocol: 'identra-demo-oid4vci';
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants?: {
    pre_authorized_code?: CredentialOfferGrant;
  };
  metadata?: Record<string, unknown>;
}

export interface PresentationInputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  schema?: string[];
  constraints?: Record<string, unknown>;
}

export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  input_descriptors: PresentationInputDescriptor[];
}

export interface IdentraPresentationRequest {
  protocol: 'identra-demo-oid4vp';
  client_id: string;
  response_type: 'vp_token';
  response_mode: 'direct_post' | 'fragment';
  nonce: string;
  presentation_definition: PresentationDefinition;
  redirect_uri?: string;
  response_uri?: string;
  state?: string;
  metadata?: Record<string, unknown>;
}

export interface VerificationSession {
  id: string;
  request: IdentraPresentationRequest;
  status: 'created' | 'pending' | 'verified' | 'failed' | 'expired';
  createdAt: string;
  updatedAt: string;
  result?: Record<string, unknown>;
}
