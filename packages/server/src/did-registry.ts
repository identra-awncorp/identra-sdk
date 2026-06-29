import {
  type DidRegistry,
  type DidResolutionResult,
  type DidResolver,
  type IdentraDidDocument,
  validateDidDocument
} from '@identra/sdk-core';

export class InMemoryDidRegistry implements DidRegistry, DidResolver {
  private readonly documents = new Map<string, IdentraDidDocument>();
  private readonly deactivated = new Set<string>();

  async register(document: IdentraDidDocument): Promise<void> {
    const validation = validateDidDocument(document);
    if (!validation.valid) {
      throw new Error(`Invalid DID document: ${validation.errors.join('; ')}`);
    }

    this.documents.set(document.id, document);
    this.deactivated.delete(document.id);
  }

  async deactivate(did: string): Promise<void> {
    this.deactivated.add(did);
  }

  async resolve(did: string): Promise<DidResolutionResult> {
    const document = this.documents.get(did) ?? null;

    if (this.deactivated.has(did)) {
      return {
        didDocument: null,
        didDocumentMetadata: { deactivated: true },
        didResolutionMetadata: { error: 'deactivated' }
      };
    }

    return {
      didDocument: document,
      didDocumentMetadata: document ? { created: document.created, updated: document.updated } : {},
      didResolutionMetadata: document
        ? { contentType: 'application/did+json' }
        : { error: 'notFound', message: `DID not found: ${did}` }
    };
  }
}
