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
/** The size cap when neither the guard nor the call names one. */
export const DEFAULT_MAX_BYTES = 262_144;
/** Protocol responses (offer, metadata, token, nonce, credential); a credential is at most 16 KB. */
export const PROTOCOL_MAX_BYTES = 65_536;

/**
 * A host the wallet may contact: a DNS name with a dot, not ending in one, not `localhost` or under
 * `.localhost`, and not an IP literal (WHATWG URL turns every IPv4 spelling into dotted decimal;
 * IPv6 literals keep their brackets).
 */
function acceptableHost(hostname: string): boolean {
  if (hostname.startsWith('[') || /^[0-9.]+$/.test(hostname)) return false;
  if (!hostname.includes('.') || hostname.endsWith('.')) return false;
  return hostname !== 'localhost' && !hostname.endsWith('.localhost');
}

/** The origin of an https URL without userinfo on an acceptable host, or null. */
export function httpsOrigin(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  return u.protocol === 'https:' && u.username === '' && u.password === '' && acceptableHost(u.hostname) ? u.origin : null;
}

/**
 * `o.maxBytes` and `o.timeoutMs` are ceilings: a call may ask for less (`init.maxBytes`,
 * `init.timeoutMs`), never for more. Both are passed down to `inner`, which must enforce them too.
 */
export function guardFetch(inner: HttpFetch, o: { allow(url: string, origin: string): boolean; timeoutMs: number; maxBytes?: number }): HttpFetch {
  const ceiling = o.maxBytes ?? DEFAULT_MAX_BYTES;
  return async (url, init) => {
    const origin = httpsOrigin(url);
    if (origin === null || !o.allow(url, origin)) throw new WalletFetchError('URL_NOT_ALLOWED', `refused to contact ${origin ?? 'a non-https URL'}`);
    const timeoutMs = Math.min(init?.timeoutMs ?? o.timeoutMs, o.timeoutMs);
    const maxBytes = Math.min(init?.maxBytes ?? ceiling, ceiling);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new WalletFetchError('NETWORK_ERROR', `no answer from ${origin} within ${timeoutMs} ms`)), timeoutMs);
    });
    try {
      const response = await Promise.race([
        inner(url, { ...init, timeoutMs, maxBytes }).catch((e: unknown) => {
          throw e instanceof WalletFetchError ? e : new WalletFetchError('NETWORK_ERROR', `${origin} is unreachable`);
        }),
        timeout,
      ]);
      if (response.status >= 300 && response.status < 400) throw new WalletFetchError('ISSUER_ERROR', `${origin} answered with a redirect`);
      const declared = Number(response.headers.get('content-length') ?? '0');
      if (!(declared <= maxBytes)) throw new WalletFetchError('ISSUER_ERROR', `${origin} sent more than ${maxBytes} bytes`);
      const body = response.text().catch(() => {
        throw new WalletFetchError('NETWORK_ERROR', `${origin} broke off the response`);
      });
      const text = await Promise.race([body, timeout]);
      if (text.length > maxBytes) throw new WalletFetchError('ISSUER_ERROR', `${origin} sent more than ${maxBytes} bytes`);
      return { status: response.status, headers: response.headers, text: async () => text };
    } finally {
      clearTimeout(timer);
    }
  };
}
