// @identra/sdk-client/product: the product page (ADR-0012) verifies a product's whole event chain
// in the browser against the pinned root. Separate entry point: it carries sdk-core's verifier, and
// the main entry must stay free of it. The only network requests are the events, the trust list
// and the status lists the policy allows (never one on behalf of an issuer outside the trust list).
import {
  createCertificateChainValidator,
  createMappedFetch,
  createSignedTrustListRegistry,
  createStatusListChecker,
  formatDigitalLinkPath,
  parseUtcInstant,
  PRODUCT_CHAIN_LIMITS,
  verifyProductChain,
  type HttpFetch,
  type ProductChainResult,
} from '@identra/sdk-core';
import { webCryptoHasher, webCryptoVerifier } from '@identra/sdk-core/webcrypto';

export type { ProductChainEvent, ProductChainResult, ProductChainState, ProductEventView } from '@identra/sdk-core';

/** Cap on any response body: 20 events of 16 KB plus the envelope (also above the 256 KB trust list). */
export const PRODUCT_RESPONSE_MAX_BYTES = PRODUCT_CHAIN_LIMITS.maxTotalBytes + 4096;
const EVENTS_TIMEOUT_MS = 5000;

export interface ProductView {
  state: 'ok' | 'not_found' | 'network_error' | 'invalid_response';
  gtin: string;
  serial: string;
  /** Only with state 'ok'. */
  result?: ProductChainResult;
  /** ISO instant of the local clock used for the verification. */
  verifiedAt: string;
  /**
   * The store's clock (`serverTime` of the response envelope) and the local clock minus it, in
   * seconds, when the store sent one. A HINT only, for the "giờ máy chưa đúng" message of ADR-0012
   * requirement 5 next to certificates that look not yet valid or a trust list that looks expired:
   * the store is not trusted and no check uses it.
   */
  serverTime?: string;
  clockSkewSeconds?: number;
}

export interface ProductVerifier {
  load(gtin: string, serial: string): Promise<ProductView>;
}

class ResponseTooLarge extends Error {}

/** Reads the body as UTF-8, failing once it passes `max` bytes. */
async function readCapped(res: Response, max: number): Promise<string> {
  if (Number(res.headers.get('content-length')) > max) throw new ResponseTooLarge();
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      void reader.cancel().catch(() => {});
      throw new ResponseTooLarge();
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) bytes.set(c, (at += c.byteLength) - c.byteLength);
  return new TextDecoder().decode(bytes);
}

/**
 * The HttpFetch contract on the browser fetch: `timeoutMs` covers the whole exchange including the
 * body, bodies above PRODUCT_RESPONSE_MAX_BYTES are refused, no redirect, no cookies, no referrer,
 * no HTTP cache (sdk-core applies its own freshness rules).
 */
function browserHttpFetch(fetchFn: typeof fetch): HttpFetch {
  return async (url, init = {}) => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error('timeout'));
      }, init.timeoutMs ?? EVENTS_TIMEOUT_MS);
    });
    const exchange = (async () => {
      const res = await fetchFn(url, {
        method: init.method ?? 'GET',
        ...(init.headers ? { headers: init.headers } : {}),
        ...(init.body !== undefined ? { body: init.body } : {}),
        cache: 'no-store',
        redirect: 'error',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      const text = await readCapped(res, PRODUCT_RESPONSE_MAX_BYTES);
      return { status: res.status, headers: res.headers, text: async () => text };
    })();
    exchange.catch(() => {}); // a late failure after the timeout must not go unhandled
    try {
      return await Promise.race([exchange, timeout]);
    } finally {
      clearTimeout(timer);
    }
  };
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function createProductVerifier(options: {
  /** Where requests for the canonical API origin actually go, e.g. `http://127.0.0.1:4000`. */
  apiBaseUrl: string;
  canonicalApiOrigin?: string;
  /** DER of the pinned Identra root certificate(s), part of the website bundle. */
  rootCertificates: Uint8Array[];
  fetch?: typeof fetch;
  /** Milliseconds since the epoch; defaults to Date.now. */
  now?: () => number;
}): ProductVerifier {
  const canonical = options.canonicalApiOrigin ?? 'https://api-identra.awncorp.vn';
  const fetchFn = options.fetch ?? ((...a: Parameters<typeof fetch>) => globalThis.fetch(...a));
  const now = options.now ?? Date.now;
  const clock = { now: () => new Date(now()) };
  // Identifiers stay canonical; only the network access goes to apiBaseUrl (validated here).
  const http = createMappedFetch(browserHttpFetch(fetchFn), { [canonical]: options.apiBaseUrl });
  // Trust list and status lists come only from the canonical API, whatever a trusted certificate's
  // SAN (and so a credential's iss and status uri) says: nothing else is ever requested.
  const lists: HttpFetch = (url, init) =>
    url === `${canonical}/trust-list` || url.startsWith(`${canonical}/issuers/`) ? http(url, init) : Promise.reject(new Error('not a canonical API URL'));
  const verifier = webCryptoVerifier;
  const chainValidator = createCertificateChainValidator({ trustedRoots: options.rootCertificates, verifier, hasher: webCryptoHasher });
  const trustRegistry = createSignedTrustListRegistry({ url: `${canonical}/trust-list`, fetch: lists, verifier, chainValidator, clock });
  const statusChecker = createStatusListChecker({ fetch: lists, verifier, chainValidator, trustRegistry, clock });

  return {
    async load(gtin, serial) {
      const path = formatDigitalLinkPath(gtin, serial); // TypeError for an invalid GTIN or serial
      const encodedSerial = path.slice(path.lastIndexOf('/') + 1);
      const view = (state: ProductView['state'], extra: Partial<ProductView> = {}): ProductView => ({
        state, gtin, serial, verifiedAt: clock.now().toISOString(), ...extra,
      });
      let status: number;
      let text: string;
      try {
        const res = await http(`${canonical}/v1/products/${gtin}/${encodedSerial}/events`, { method: 'GET', headers: { accept: 'application/json' }, timeoutMs: EVENTS_TIMEOUT_MS });
        status = res.status;
        text = await res.text();
      } catch (e) {
        return view(e instanceof ResponseTooLarge ? 'invalid_response' : 'network_error');
      }
      if (status === 404) return view('not_found');
      if (status !== 200) return view('network_error');
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return view('invalid_response');
      }
      if (!isObject(body) || body['gtin'] !== gtin || body['serial'] !== serial || !Array.isArray(body['events'])) return view('invalid_response');
      const hasServerTime = Object.hasOwn(body, 'serverTime');
      const serverMs = hasServerTime ? parseUtcInstant(body['serverTime']) : null;
      if (hasServerTime && serverMs === null) return view('invalid_response');
      const now = clock.now();
      const result = await verifyProductChain(
        { gtin, serial, events: body['events'] },
        { verifier, hasher: webCryptoHasher, chainValidator, trustRegistry, statusChecker, now },
      );
      const hint = serverMs === null ? {} : { serverTime: body['serverTime'] as string, clockSkewSeconds: Math.round((now.getTime() - serverMs) / 1000) };
      return view('ok', { result, ...hint });
    },
  };
}
