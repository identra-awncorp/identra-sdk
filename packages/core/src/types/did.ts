export type Did = `did:${string}:${string}`;

export interface IdentraVerificationMethod {
  id: string;
  type: string;
  controller: Did | string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyMultibase?: string;
}

export interface IdentraDidService {
  id: string;
  type: string;
  serviceEndpoint: string | string[] | Record<string, unknown>;
}

export interface IdentraDidDocument {
  '@context': string | string[];
  id: Did | string;
  controller?: Did | string | Array<Did | string>;
  verificationMethod?: IdentraVerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  service?: IdentraDidService[];
  created?: string;
  updated?: string;
}

export interface DidResolutionMetadata {
  contentType?: string;
  error?: string;
  message?: string;
}

export interface DidDocumentMetadata {
  created?: string;
  updated?: string;
  deactivated?: boolean;
  [key: string]: unknown;
}

export interface DidResolutionResult {
  didDocument: IdentraDidDocument | null;
  didDocumentMetadata: DidDocumentMetadata;
  didResolutionMetadata: DidResolutionMetadata;
}

export interface DidResolver {
  resolve(did: Did | string): Promise<DidResolutionResult>;
}

export interface DidRegistry {
  register(document: IdentraDidDocument): Promise<void>;
  deactivate(did: Did | string): Promise<void>;
}
