// Identifiers are always canonical https URLs (ADR-0015 section 11). Development and test
// deployments send the NETWORK access for a canonical origin to another origin, without changing
// any identifier: the status list `sub`, `iss` and the trust list URL stay canonical.
import type { HttpFetch } from './interfaces.js';

const ORIGIN = /^https?:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?$/;

/**
 * `map` is `{ 'https://api-identra.awncorp.vn': 'http://127.0.0.1:4000' }`. A URL is rewritten only
 * when it is a mapped origin exactly or continues with `/`, `?` or `#` right after it; every other
 * URL goes to `fetch` unchanged. Nothing else is added: no redirect handling, no retries.
 */
export function createMappedFetch(fetch: HttpFetch, map: Record<string, string>): HttpFetch {
  if (typeof fetch !== 'function') throw new TypeError('fetch is required');
  const entries = Object.entries(map ?? {});
  for (const [canonical, actual] of entries) {
    if (!ORIGIN.test(canonical) || !canonical.startsWith('https://')) throw new TypeError('a canonical origin must be https://host[:port] without a path');
    if (typeof actual !== 'string' || !ORIGIN.test(actual)) throw new TypeError('an actual origin must be http(s)://host[:port] without a path');
  }
  return (url, init) => {
    for (const [canonical, actual] of entries) {
      if (url.startsWith(canonical) && (url.length === canonical.length || '/?#'.includes(url[canonical.length]!))) {
        return fetch(actual + url.slice(canonical.length), init);
      }
    }
    return fetch(url, init);
  };
}
