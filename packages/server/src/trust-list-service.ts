// The signed trust list served at https://api-identra.awncorp.vn/trust-list (ADR-0013 sections 6-7,
// ADR-0015 section 6): re-signed when the source content changed or the cached token is older than
// one hour. An invalid source is an error: the operator must fix the file; nothing is signed.
import { createTrustListToken, validateTrustListContent, type Clock } from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

const RESIGN_AFTER_MS = 3600_000;

export interface TrustListService {
  token(): Promise<string>;
}

export function createTrustListService(options: {
  /** The trust list content `{ issuers, verifiers }`; the server reads it from a JSON file. */
  source: () => unknown;
  keyStore: IssuerKeyStore;
  clock: Clock;
}): TrustListService {
  const { source, keyStore, clock } = options;
  let held: { token: string; content: string; signedAt: number } | undefined;
  return {
    async token() {
      const raw = await source();
      // The core validator also checks every fingerprint: 43 base64url characters decoding to 32 bytes.
      const v = validateTrustListContent(raw);
      if (!v.ok) throw new Error(`trust list source is invalid: ${v.detail}`);
      const content = JSON.stringify(v.value);
      const now = clock.now();
      if (held && held.content === content && now.getTime() - held.signedAt < RESIGN_AFTER_MS) return held.token;
      const token = await createTrustListToken({ ...v.value, signer: await keyStore.trustListSigner(), now });
      held = { token, content, signedAt: now.getTime() };
      return token;
    },
  };
}
