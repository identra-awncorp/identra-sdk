// The signed trust list served at https://api-identra.awncorp.vn/trust-list (ADR-0013 sections 6-7,
// ADR-0015 section 6, ADR-0019): re-signed when the source content changed or the token is an hour
// old, with an iat strictly greater than the previous one. When the source becomes invalid, the
// last good token is served unchanged until its exp and `onError` is told; with no good token the
// call throws.
import { createTrustListToken, decodeJws, utf8Decode, validateTrustListContent, TRUST_LIST_TOKEN_MAX_BYTES, type Clock } from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

const RESIGN_AFTER_MS = 3600_000;
const LIFETIME_SECONDS = 86_400;

export interface TrustListService {
  token(): Promise<string>;
}

/** iat of a token this service produced earlier (read, not verified: it only raises the next iat). */
function iatOf(token: string): number {
  const d = decodeJws(token, TRUST_LIST_TOKEN_MAX_BYTES);
  const iat = d.ok ? (JSON.parse(utf8Decode(d.jws.payload)) as { iat?: unknown }).iat : undefined;
  if (!Number.isSafeInteger(iat)) throw new TypeError('lastToken is not a token with an integer iat');
  return iat as number;
}

export function createTrustListService(options: {
  /** The trust list content `{ issuers, verifiers }`; the server reads it from a JSON file. */
  source: () => unknown;
  keyStore: IssuerKeyStore;
  clock: Clock;
  /** ADR-0019 section 2: set to the new signer certificate's notBefore after replacing a compromised one. */
  signerNotBefore?: number;
  /**
   * The last token served before a restart, if the server kept it: the next iat is then greater
   * than its iat. Without it, a restart within the same second as the last signature (or after
   * the clock stepped back) can produce an iat that is not greater; clients then keep their held copy.
   */
  lastToken?: string;
  /** Told why the source was refused while the last good token is still served. */
  onError?: (error: Error) => void;
}): TrustListService {
  const { source, keyStore, clock, signerNotBefore, onError } = options;
  let lastIat = options.lastToken === undefined ? 0 : iatOf(options.lastToken);
  let held: { token: string; content: string; signedAt: number; exp: number } | undefined;
  return {
    async token() {
      const now = clock.now();
      let content: string;
      let value;
      try {
        // The core validator also checks every fingerprint: 43 base64url characters decoding to 32 bytes.
        const v = validateTrustListContent(await source());
        if (!v.ok) throw new Error(`trust list source is invalid: ${v.detail}`);
        value = v.value;
        content = JSON.stringify(value);
      } catch (e) {
        const error = e instanceof Error ? e : new Error('trust list source failed');
        if (!held || held.exp * 1000 <= now.getTime()) throw error;
        onError?.(error);
        return held.token;
      }
      const age = now.getTime() - (held?.signedAt ?? 0);
      if (held && held.content === content && age >= 0 && age < RESIGN_AFTER_MS) return held.token;
      const iat = Math.max(Math.floor(now.getTime() / 1000), lastIat + 1);
      const token = await createTrustListToken({
        ...value, signer: await keyStore.trustListSigner(), now: new Date(iat * 1000), lifetimeSeconds: LIFETIME_SECONDS,
        ...(signerNotBefore !== undefined ? { signerNotBefore } : {}),
      });
      lastIat = iat;
      held = { token, content, signedAt: now.getTime(), exp: iat + LIFETIME_SECONDS };
      return token;
    },
  };
}
