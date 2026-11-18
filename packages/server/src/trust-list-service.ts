// The signed trust list served at https://api-identra.awncorp.vn/trust-list (ADR-0013 sections 6-7,
// ADR-0015 section 6, ADR-0019): re-signed when the source content changed or the token is an hour
// old, with an iat strictly greater than the previous one and never more than 5 s ahead of the
// clock, by a signer certificate valid at that moment, carrying signer_not_before (ADR-0019 section 2).
// When the source becomes invalid or signing is not allowed, the last good token is served unchanged
// until its exp and `onError` is told the reason; with no good token the call throws. Neither the
// reason nor the error quotes the source (it may be file content).
import {
  base64Decode, createTrustListToken, decodeJws, parseCertificate, utf8Decode, validateTrustListContent, TRUST_LIST_TOKEN_MAX_BYTES, type Clock,
} from '@identra/sdk-core';
import type { IssuerKeyStore } from './key-store.js';

const RESIGN_AFTER_MS = 3600_000;
const LIFETIME_SECONDS = 86_400;
/** A re-signed token's iat is at most this far ahead of the clock (rapid source changes wait instead). */
const MAX_IAT_LEAD_SECONDS = 5;
/** Verifiers accept an iat up to 60 s ahead; a remembered lastIat beyond that is ignored (and reported). */
const MAX_STORED_LEAD_SECONDS = 60;

export interface TrustListService {
  token(): Promise<string>;
  /** The token held now, for monitoring (ADR-0014 section 7): seconds; null before the first one. */
  current(): { iat: number; exp: number; issuers: number; verifiers: number; signerNotAfter: number } | null;
}

/** Why the held token is served instead of a new one (or, with none held, why the call throws). */
export type TrustListProblem = 'source_invalid' | 'source_threw' | 'signer_expired' | 'last_iat_in_future';

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
  /**
   * ADR-0019 section 2: `signer_not_before` is published by default as the signer certificate's own
   * notBefore; this overrides it (it may not be later than that notBefore).
   */
  signerNotBefore?: number;
  /**
   * The last token served before a restart, if the server kept it: the next iat is then greater
   * than its iat. Without it (or lastIatStore), a restart within the same second as the last
   * signature (or after the clock stepped back) can produce an iat that is not greater; clients then
   * keep their held copy.
   */
  lastToken?: string;
  /** Told why the held token is served instead of a new one. */
  onError?: (reason: TrustListProblem) => void;
  /**
   * Read once before the first signature and written after each one, so iat stays strictly
   * increasing across restarts. A failing store fails the call (no token with an unrecorded iat).
   */
  lastIatStore?: LastIatStore;
}): TrustListService {
  const { source, keyStore, clock, onError, lastIatStore } = options;
  let lastIat: number | undefined; // read on the first signature
  let held: { token: string; content: string; signedAt: number; exp: number; issuers: number; verifiers: number; signerNotAfter: number } | undefined;

  /** The held token while inside its exp, reporting `reason`; else the call fails with it. */
  const fallback = (reason: TrustListProblem, now: Date): string => {
    if (!held || held.exp * 1000 <= now.getTime()) throw new Error(`trust list ${reason}`);
    onError?.(reason);
    return held.token;
  };

  /** lastToken and lastIatStore, each ignored (and reported) when more than 60 s ahead of the clock. */
  async function rememberedIat(nowS: number): Promise<number> {
    const stored = lastIatStore ? await lastIatStore.get() : null;
    if (stored !== null && !Number.isSafeInteger(stored)) throw new TypeError('lastIatStore.get() must give an integer or null');
    let iat = 0;
    for (const candidate of [options.lastToken === undefined ? null : iatOf(options.lastToken), stored]) {
      if (candidate === null) continue;
      if (candidate > nowS + MAX_STORED_LEAD_SECONDS) onError?.('last_iat_in_future');
      else iat = Math.max(iat, candidate);
    }
    return iat;
  }

  return {
    current: () => (held ? { iat: held.exp - LIFETIME_SECONDS, exp: held.exp, issuers: held.issuers, verifiers: held.verifiers, signerNotAfter: held.signerNotAfter } : null),
    async token() {
      const now = clock.now();
      const nowS = Math.floor(now.getTime() / 1000);
      let content: string;
      let value;
      let problem: TrustListProblem = 'source_threw';
      try {
        const raw = await source();
        problem = 'source_invalid';
        // The core validator also checks every fingerprint: 43 base64url characters decoding to 32 bytes.
        const v = validateTrustListContent(raw);
        if (!v.ok) throw new Error();
        value = v.value;
        content = JSON.stringify(value);
      } catch {
        return fallback(problem, now);
      }
      const age = now.getTime() - (held?.signedAt ?? 0);
      if (held && held.content === content && age >= 0 && age < RESIGN_AFTER_MS) return held.token;
      const signer = await keyStore.trustListSigner();
      const cert = parseCertificate(base64Decode(signer.x5c![0]!));
      if (now < cert.notBefore || now > cert.notAfter) return fallback('signer_expired', now);
      lastIat ??= await rememberedIat(nowS);
      const iat = Math.max(nowS, lastIat + 1);
      // Rapid changes wait for the clock instead of pushing iat ahead (verifiers refuse > 60 s ahead).
      if (iat > nowS + (held ? MAX_IAT_LEAD_SECONDS : MAX_STORED_LEAD_SECONDS)) {
        if (held && held.exp * 1000 > now.getTime()) return held.token;
        throw new Error('trust list: the next iat would run ahead of the clock');
      }
      const token = await createTrustListToken({
        ...value, signer, now: new Date(iat * 1000), lifetimeSeconds: LIFETIME_SECONDS,
        signerNotBefore: options.signerNotBefore ?? Math.floor(cert.notBefore.getTime() / 1000),
      });
      lastIat = iat;
      await lastIatStore?.set(iat);
      held = {
        token, content, signedAt: now.getTime(), exp: iat + LIFETIME_SECONDS, issuers: value.issuers.length, verifiers: value.verifiers.length,
        signerNotAfter: Math.floor(cert.notAfter.getTime() / 1000),
      };
      return token;
    },
  };
}
