// The signed trust list served at https://api-identra.awncorp.vn/trust-list (ADR-0013 sections 6-7,
// ADR-0015 section 6, ADR-0019): re-signed when the source content changed or the token is an hour
// old, with an iat strictly greater than the previous one. When the source becomes invalid, the
// last good token is served unchanged until its exp and `onError` is told the reason; with no good
// token the call throws. Neither the reason nor the error quotes the source (it may be file content).
import { createTrustListToken, decodeJws, utf8Decode, validateTrustListContent, TRUST_LIST_TOKEN_MAX_BYTES, type Clock } from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

const RESIGN_AFTER_MS = 3600_000;
const LIFETIME_SECONDS = 86_400;

export interface TrustListService {
  token(): Promise<string>;
  /** The token held now, for monitoring (ADR-0014 section 7); null before the first one. */
  current(): { iat: number; exp: number; issuers: number; verifiers: number } | null;
}

export type TrustListSourceProblem = 'source_invalid' | 'source_threw';

/** Keeps the last signed iat across restarts (e.g. one row in the server's database). */
export interface LastIatStore {
  get(): Promise<number | null>;
  set(iat: number): Promise<void>;
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
  onError?: (reason: TrustListSourceProblem) => void;
  /**
   * Read once before the first signature and written after each one, so iat stays strictly
   * increasing across restarts. A failing store fails the call (no token with an unrecorded iat).
   */
  lastIatStore?: LastIatStore;
}): TrustListService {
  const { source, keyStore, clock, signerNotBefore, onError, lastIatStore } = options;
  let lastIat = options.lastToken === undefined ? 0 : iatOf(options.lastToken);
  let storedIatRead = lastIatStore === undefined;
  let held: { token: string; content: string; signedAt: number; exp: number; issuers: number; verifiers: number } | undefined;
  return {
    current: () => (held ? { iat: held.exp - LIFETIME_SECONDS, exp: held.exp, issuers: held.issuers, verifiers: held.verifiers } : null),
    async token() {
      const now = clock.now();
      let content: string;
      let value;
      let problem: TrustListSourceProblem = 'source_threw';
      try {
        const raw = await source();
        problem = 'source_invalid';
        // The core validator also checks every fingerprint: 43 base64url characters decoding to 32 bytes.
        const v = validateTrustListContent(raw);
        if (!v.ok) throw new Error();
        value = v.value;
        content = JSON.stringify(value);
      } catch {
        if (!held || held.exp * 1000 <= now.getTime()) throw new Error(`trust list ${problem}`);
        onError?.(problem);
        return held.token;
      }
      const age = now.getTime() - (held?.signedAt ?? 0);
      if (held && held.content === content && age >= 0 && age < RESIGN_AFTER_MS) return held.token;
      if (!storedIatRead) {
        const stored = await lastIatStore!.get();
        if (stored !== null && !Number.isSafeInteger(stored)) throw new TypeError('lastIatStore.get() must give an integer or null');
        lastIat = Math.max(lastIat, stored ?? 0);
        storedIatRead = true;
      }
      const iat = Math.max(Math.floor(now.getTime() / 1000), lastIat + 1);
      const token = await createTrustListToken({
        ...value, signer: await keyStore.trustListSigner(), now: new Date(iat * 1000), lifetimeSeconds: LIFETIME_SECONDS,
        ...(signerNotBefore !== undefined ? { signerNotBefore } : {}),
      });
      lastIat = iat;
      await lastIatStore?.set(iat);
      held = { token, content, signedAt: now.getTime(), exp: iat + LIFETIME_SECONDS, issuers: value.issuers.length, verifiers: value.verifiers.length };
      return token;
    },
  };
}
