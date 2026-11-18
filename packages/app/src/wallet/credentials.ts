// The credentials the wallet holds: list (no decryption), display data, status refresh, removal.
import { base64Decode, base64UrlEncode, decodeCredentialUnverified, verifyStoredCredential } from '@identra/sdk-core';
import { CredentialVaultError, type CredentialMetadata, type StoredCredentialStatus } from '../credential-vault.js';
import type { WalletContext } from './context.js';
import { WalletErrorCodes as C, type WalletFailure } from './errors.js';

/** `unknown`: the status, the trust list, or another check could not confirm the credential (ADR-0013 section 4, "chưa kiểm được trạng thái"). */
export type WalletCredentialStatus = 'valid' | 'revoked' | 'suspended' | 'unknown';
const toWallet = (s: StoredCredentialStatus | null): WalletCredentialStatus | null => (s === 'unavailable' ? 'unknown' : s);
const summaryOf = (r: CredentialMetadata): CredentialSummary => ({
  id: r.id, vct: r.vct, issuerUri: r.issuer, status: toWallet(r.status_cache), statusCheckedAt: r.status_checked_at, createdAt: r.created_at,
});

/** The trust-list name of the issuer whose x5c leaf signed a stored credential; null while it cannot be read. */
export async function issuerNameOf(ctx: WalletContext, x5c: unknown): Promise<string | null> {
  try {
    const leaf = base64Decode((x5c as string[])[0]!);
    return (await ctx.trustRegistry.lookup(base64UrlEncode(await ctx.hasher.sha256(leaf)), ctx.clock.now()))?.ten ?? null;
  } catch {
    return null;
  }
}

export interface CredentialSummary {
  id: string;
  vct: string;
  issuerUri: string;
  /** Cached by refreshStatus (and set to valid on receipt). */
  status: WalletCredentialStatus | null;
  statusCheckedAt: string | null;
  createdAt: string;
}

export interface CredentialDetails extends CredentialSummary {
  /** From the trust list; null while it cannot be read. */
  issuerName: string | null;
  iat: number;
  /** The disclosed subject claims, as stored. Display only: decoded, not re-verified. */
  claims: Record<string, unknown>;
}

export function createCredentials(ctx: WalletContext) {

  /** The stored compact, or a failure: CREDENTIAL_NOT_FOUND, or STORAGE_ERROR when the vault cannot open it. */
  async function open(id: string): Promise<{ ok: true; compact: string } | WalletFailure> {
    try {
      return { ok: true, compact: await ctx.vault.open(id) };
    } catch (e) {
      return { ok: false, code: e instanceof CredentialVaultError && e.code === 'NOT_FOUND' ? C.CREDENTIAL_NOT_FOUND : C.STORAGE_ERROR };
    }
  }

  return {
    async list(): Promise<CredentialSummary[]> {
      return (await ctx.vault.list()).map(summaryOf);
    },

    async get(id: string): Promise<{ ok: true; credential: CredentialDetails } | WalletFailure> {
      const opened = await open(id);
      if (!opened.ok) return opened;
      const row = await ctx.vault.getMeta(id);
      if (!row) return { ok: false, code: C.CREDENTIAL_NOT_FOUND };
      const { header, payload, disclosures } = decodeCredentialUnverified(opened.compact);
      return {
        ok: true,
        credential: {
          ...summaryOf(row),
          issuerName: await issuerNameOf(ctx, header['x5c']),
          iat: payload['iat'] as number,
          claims: Object.fromEntries(disclosures.map((d) => [d.name, d.value])),
        },
      };
    },

    /** Re-runs verifyStoredCredential and caches the answer; anything but a definite status is `unknown`. */
    async refreshStatus(id: string): Promise<{ ok: true; status: WalletCredentialStatus; checks: WalletFailure['checks'] & object } | WalletFailure> {
      const opened = await open(id);
      if (!opened.ok) return opened;
      const r = await verifyStoredCredential(opened.compact, {
        verifier: ctx.verifier, hasher: ctx.hasher, chainValidator: ctx.chainValidator, trustRegistry: ctx.trustRegistry,
        statusChecker: ctx.statusChecker, supportedVcts: ctx.supportedVcts, now: ctx.clock.now(),
      });
      const statusCode = r.checks.find((c) => c.id === 'status')?.code;
      const status: StoredCredentialStatus = r.ok ? 'valid' : statusCode === 'REVOKED' ? 'revoked' : statusCode === 'SUSPENDED' ? 'suspended' : 'unavailable';
      try {
        await ctx.vault.setStatus(id, status, ctx.clock.now());
      } catch (e) {
        return { ok: false, code: e instanceof CredentialVaultError && e.code === 'NOT_FOUND' ? C.CREDENTIAL_NOT_FOUND : C.STORAGE_ERROR };
      }
      return { ok: true, status: toWallet(status)!, checks: r.checks };
    },

    /** Deletes the row and its wallet key; removing an unknown id succeeds. */
    async remove(id: string): Promise<{ ok: true } | WalletFailure> {
      try {
        await ctx.vault.removeWithKey(id, ctx.keyStore);
        return { ok: true };
      } catch {
        return { ok: false, code: C.STORAGE_ERROR };
      }
    },
  };
}
