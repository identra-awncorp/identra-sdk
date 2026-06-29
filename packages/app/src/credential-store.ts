import type { IdentraVerifiableCredential } from '@identra/sdk-core';

export interface CredentialStore {
  saveCredential(credential: IdentraVerifiableCredential): Promise<void>;
  listCredentials(): Promise<IdentraVerifiableCredential[]>;
  getCredential(id: string): Promise<IdentraVerifiableCredential | null>;
}

export class InMemoryCredentialStore implements CredentialStore {
  private readonly credentials = new Map<string, IdentraVerifiableCredential>();

  async saveCredential(credential: IdentraVerifiableCredential): Promise<void> {
    this.credentials.set(credential.id, credential);
  }

  async listCredentials(): Promise<IdentraVerifiableCredential[]> {
    return Array.from(this.credentials.values());
  }

  async getCredential(id: string): Promise<IdentraVerifiableCredential | null> {
    return this.credentials.get(id) ?? null;
  }
}
