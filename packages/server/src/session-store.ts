import type { VerificationSession } from '@identra/sdk-core';

export interface VerificationSessionStore {
  save(session: VerificationSession): Promise<void>;
  get(id: string): Promise<VerificationSession | null>;
  update(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession>;
}

export class InMemoryVerificationSessionStore implements VerificationSessionStore {
  private readonly sessions = new Map<string, VerificationSession>();

  async save(session: VerificationSession): Promise<void> {
    this.sessions.set(session.id, session);
  }

  async get(id: string): Promise<VerificationSession | null> {
    return this.sessions.get(id) ?? null;
  }

  async update(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession> {
    const current = this.sessions.get(id);
    if (!current) throw new Error(`Verification session not found: ${id}`);

    const next = {
      ...current,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.sessions.set(id, next);
    return next;
  }
}
