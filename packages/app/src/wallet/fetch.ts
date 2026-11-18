// The one place the wallet wraps the injected HttpFetch (docs/architecture.md section 8): https
// only, no credentials in the URL, only the URLs `allow` admits, a timeout, no redirect (a 3xx is
// refused, never followed) and a response size cap. The app's own fetch must not follow redirects
// either: a followed redirect is invisible here.
import type { HttpFetch } from '@identra/sdk-core';

export type WalletFetchErrorCode = 'NETWORK_ERROR' | 'URL_NOT_ALLOWED' | 'ISSUER_ERROR';

/** Carries a code only; never the URL's query, a body or a header value. */
export class WalletFetchError extends Error {
  readonly code: WalletFetchErrorCode;
  constructor(code: WalletFetchErrorCode, message: string) {
    super(message);
    this.name = 'WalletFetchError';
    this.code = code;
  }
}

export const PROTOCOL_TIMEOUT_MS = 10_000;
/** Protocol responses (offer, metadata, token, nonce, credential); a credential is at most 16 KB. */
export const PROTOCOL_MAX_BYTES = 65_536;

/** The origin of an https URL without userinfo, or null. */
export function httpsOrigin(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  return u.protocol === 'https:' && u.username === '' && u.password === '' ? u.origin : null;
}

export function guardFetch(inner: HttpFetch, o: { allow(url: string, origin: string): boolean; maxBytes: number; timeoutMs: number }): HttpFetch {
  return async (url, init) => {
    const origin = httpsOrigin(url);
    if (origin === null || !o.allow(url, origin)) throw new WalletFetchError('URL_NOT_ALLOWED', `refused to contact ${origin ?? 'a non-https URL'}`);
    const timeoutMs = Math.min(init?.timeoutMs ?? o.timeoutMs, o.timeoutMs);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new WalletFetchError('NETWORK_ERROR', `no answer from ${origin} within ${timeoutMs} ms`)), timeoutMs);
    });
    try {
      const response = await Promise.race([
        inner(url, { ...init, timeoutMs }).catch((e: unknown) => {
          throw e instanceof WalletFetchError ? e : new WalletFetchError('NETWORK_ERROR', `${origin} is unreachable`);
        }),
        timeout,
      ]);
      if (response.status >= 300 && response.status < 400) throw new WalletFetchError('ISSUER_ERROR', `${origin} answered with a redirect`);
      const declared = Number(response.headers.get('content-length') ?? '0');
      if (!(declared <= o.maxBytes)) throw new WalletFetchError('ISSUER_ERROR', `${origin} sent more than ${o.maxBytes} bytes`);
      const body = response.text().catch(() => {
        throw new WalletFetchError('NETWORK_ERROR', `${origin} broke off the response`);
      });
      const text = await Promise.race([body, timeout]);
      if (text.length > o.maxBytes) throw new WalletFetchError('ISSUER_ERROR', `${origin} sent more than ${o.maxBytes} bytes`);
      return { status: response.status, headers: response.headers, text: async () => text };
    } finally {
      clearTimeout(timer);
    }
  };
}
